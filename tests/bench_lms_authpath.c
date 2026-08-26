/* LMS Sign auth-path performance benchmark (design doc step 6a: PC performance quantification table).
 *
 * Compares two auth-path generation modes while signing several messages consecutively
 * (q increasing) with the same key:
 *   - baseline: default lms_tree_node recursive rebuild (no backend registered; current
 *     state, root cause of slow Sign);
 *   - cache: registers the lms_subtree backend (lms_subtree_auth_path_backend), with a
 *     one-time sign_init (builds the cache); afterwards each sign does sign_advance
 *     hits/boundary rebuilds + table lookup.
 *
 * Parameter set (RFC 8554 legal values): n=32 (SHA256, fixed), h in {5,10,15}, w=4 (fixed).
 * The independent variable of this benchmark is "sign count" (how many consecutive
 * messages are signed), **not the RFC parameter n**.
 *
 * Metrics:
 *   - total wall-clock time (clock(); relative comparison on a PC; tree hashing and
 *     LM-OTS public keys are both SHA256, and time is proportional to total SHA256
 *     compression, so the relative comparison is fair);
 *   - lmots_chain_stats (calls/steps, the LM-OTS chain portion, corresponding to
 *     on-board cycle=calls+67*steps).
 *     baseline's recursion repeatedly recomputes the LM-OTS public keys covered by the
 *     auth path (counted in calls/steps); with cache hits this portion is 0 (only the
 *     signature's own LM-OTS signing remains), and that difference is the speedup source.
 *   - cache's one-time sign_init cost (listed separately) + amortized per-sign cost.
 *
 * Results feed the paper's P0 performance comparison table ("tree cache reduces the Sign
 * auth path from per-sign recomputation to amortized O(h) table lookup").
 *
 * Environment: PC, MinGW gcc c99, -O2. This program is not part of make test (benchmark only).
 */

#include "../src/lms_internal.h"
#include "../src/lms_subtree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Injected allocator: malloc/free on the PC (lms_subtree does not call malloc directly). */
static void *bench_alloc(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}
static void bench_free(void *context, void *ptr)
{
    (void)context;
    free(ptr);
}

static void make_key(lms_private_key_t *priv, uint32_t lms_type, uint32_t lmots_type)
{
    uint8_t I[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];
    uint32_t i;
    for (i = 0; i < LMS_I_LEN; i++) {
        I[i] = (uint8_t)(0x10u + i);
    }
    for (i = 0; i < LMS_SEED_LEN; i++) {
        seed[i] = (uint8_t)(0x60u + i);
    }
    lms_private_key_init(priv, lms_type, lmots_type, I, seed);
}

/* Runs sign_count consecutive signatures (q increasing from priv->q), returning total time in seconds.
 * stats_out receives cumulative chain_stats (may be NULL). Registers the backend when use_cache is nonzero. */
static double run_signs(lms_private_key_t *priv,
                        const uint8_t *msg, size_t msg_len,
                        uint32_t sign_count,
                        lms_tree_ctx_t *ctx, int use_cache,
                        lmots_chain_stats_t *stats_out)
{
    uint8_t sig[LMS_MAX_SIGNATURE_LEN];
    size_t written;
    clock_t t0;
    clock_t t1;
    uint32_t k;

    if (use_cache) {
        lms_auth_path_backend_set(lms_subtree_auth_path_backend, ctx);
    } else {
        lms_auth_path_backend_set(NULL, NULL);
    }

    lmots_chain_stats_reset();
    t0 = clock();
    for (k = 0u; k < sign_count; k++) {
        if (lms_sign(priv, msg, msg_len, sig, sizeof(sig), &written) != LMS_OK) {
            printf("ERROR: sign failed at k=%u q=%u\n", k, priv->q);
            lms_auth_path_backend_set(NULL, NULL);
            return -1.0;
        }
    }
    t1 = clock();
    if (stats_out) {
        lmots_chain_stats_get(stats_out);
    }
    lms_auth_path_backend_set(NULL, NULL);
    return (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
}

/* One comparison benchmark: baseline vs cache at the same sign_count + speedup. */
static void bench_compare(uint32_t lms_type, uint32_t lmots_type,
                          uint32_t h, uint64_t memory_target, uint32_t sign_count)
{
    static const uint8_t msg[] = "LMS auth-path benchmark message for step6a";
    lms_private_key_t priv_base;
    lms_private_key_t priv_cache;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    lmots_chain_stats_t st_base;
    lmots_chain_stats_t st_cache;
    lmots_chain_stats_t st_init;
    double t_base;
    double t_cache;
    double t_init;
    clock_t i0;
    clock_t i1;

    make_key(&priv_base, lms_type, lmots_type);
    make_key(&priv_cache, lms_type, lmots_type);

    if (lms_tree_configure(lms_type, memory_target, &cfg) != LMS_OK ||
        lms_tree_ctx_init(&ctx, &cfg, priv_cache.I, NULL, NULL,
                          bench_alloc, bench_free, NULL) != LMS_OK) {
        printf("ERROR: configure/init failed for h=%u\n", h);
        return;
    }

    /* cache: one-time sign_init (builds ACTIVE caches for all levels at q=0), timed separately. */
    lmots_chain_stats_reset();
    i0 = clock();
    if (lms_tree_sign_init(&ctx, &priv_cache) != LMS_OK) {
        printf("ERROR: sign_init failed for h=%u\n", h);
        lms_tree_ctx_free(&ctx);
        return;
    }
    i1 = clock();
    lmots_chain_stats_get(&st_init);
    t_init = (double)(i1 - i0) / (double)CLOCKS_PER_SEC;

    t_base = run_signs(&priv_base, msg, sizeof(msg), sign_count, NULL, 0, &st_base);
    t_cache = run_signs(&priv_cache, msg, sizeof(msg), sign_count, &ctx, 1, &st_cache);

    if (t_base < 0.0 || t_cache < 0.0) {
        lms_tree_ctx_free(&ctx);
        return;
    }

    printf("H%-2u j=%u sub=%u signs=%-4u\n", h, cfg.subtree_size, cfg.sublevels, sign_count);
    printf("  baseline : %9.1f ms (%8.2f ms/sign) calls=%-10llu steps=%-12llu\n",
           t_base * 1e3, t_base * 1e3 / (double)sign_count,
           (unsigned long long)st_base.calls, (unsigned long long)st_base.steps);
    printf("  cache    : %9.1f ms (%8.2f ms/sign) calls=%-10llu steps=%-12llu  [sign only]\n",
           t_cache * 1e3, t_cache * 1e3 / (double)sign_count,
           (unsigned long long)st_cache.calls, (unsigned long long)st_cache.steps);
    printf("  init     : %9.1f ms calls=%-10llu steps=%-12llu  [one-time]\n",
           t_init * 1e3,
           (unsigned long long)st_init.calls, (unsigned long long)st_init.steps);
    printf("  speedup  : sign-only %8.2fx | amortized(init+signs) %8.2fx\n\n",
           t_base / t_cache, t_base / (t_cache + t_init));

    lms_tree_ctx_free(&ctx);
}

/* Amortization curve of cache mode as the sign count grows (across subtree boundaries);
 * cache only is measured (baseline is too slow for large N).
 * Reports total cache calls/steps (including init) at several sign_count tiers to show
 * rebuild amortization. */
static void bench_cache_scaling(uint32_t lms_type, uint32_t lmots_type,
                                uint32_t h, uint64_t memory_target,
                                const uint32_t *sign_counts, size_t n_counts)
{
    static const uint8_t msg[] = "LMS auth-path benchmark cache scaling";
    lms_tree_config_t cfg;
    size_t c;

    if (lms_tree_configure(lms_type, memory_target, &cfg) != LMS_OK) {
        printf("ERROR: configure failed for h=%u\n", h);
        return;
    }
    printf("H%-2u j=%u sub=%u  cache scaling (calls/steps incl. one-time init):\n",
           h, cfg.subtree_size, cfg.sublevels);

    for (c = 0u; c < n_counts; c++) {
        uint32_t sc = sign_counts[c];
        lms_private_key_t priv;
        lms_tree_ctx_t ctx;
        lmots_chain_stats_t st_init;
        lmots_chain_stats_t st_sign;
        clock_t i0;
        clock_t i1;
        double t_init;
        double t_sign;

        make_key(&priv, lms_type, lmots_type);
        if (lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                              bench_alloc, bench_free, NULL) != LMS_OK) {
            printf("ERROR: ctx init failed\n");
            return;
        }
        lmots_chain_stats_reset();
        i0 = clock();
        if (lms_tree_sign_init(&ctx, &priv) != LMS_OK) {
            printf("ERROR: sign_init failed\n");
            lms_tree_ctx_free(&ctx);
            return;
        }
        i1 = clock();
        lmots_chain_stats_get(&st_init);
        t_init = (double)(i1 - i0) / (double)CLOCKS_PER_SEC;

        t_sign = run_signs(&priv, msg, sizeof(msg), sc, &ctx, 1, &st_sign);
        if (t_sign < 0.0) {
            lms_tree_ctx_free(&ctx);
            return;
        }
        printf("  signs=%-5u | sign %8.1f ms calls=%-9llu steps=%-11llu | init %7.1f ms | amortized %6.2f ms/sign\n",
               sc, t_sign * 1e3,
               (unsigned long long)st_sign.calls, (unsigned long long)st_sign.steps,
               t_init * 1e3,
               (t_init + t_sign) * 1e3 / (double)sc);
        lms_tree_ctx_free(&ctx);
    }
    printf("\n");
}

int main(void)
{
    static const uint32_t scaling_counts[] = {1u, 8u, 32u, 64u, 128u};

    printf("=== LMS Sign auth-path benchmark (baseline lms_tree_node vs lms_subtree cache) ===\n");
    printf("params: n=32 (SHA256), w=4, h in {5,10,15}; 'signs' = # of consecutive messages\n");
    printf("time=wall-clock; calls/steps=lmots_chain_stats (LM-OTS work, ~cycle=calls+67*steps)\n\n");

    printf("--- (1) baseline vs cache, same sign_count ---\n\n");
    /* H5: 32 leaves. j=h=5 (full-tree special case, sublevels=1). */
    bench_compare(LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4, 5u, 2300u, 32u);
    /* H10: 1024 leaves. j=5 (sublevels=2). */
    bench_compare(LMS_SHA256_N32_H10, LMOTS_SHA256_N32_W4, 10u, 16384u, 32u);
    /* H15: 32768 leaves. j=5 (sublevels=3). Small sign_count (baseline recursion is extremely slow). */
    bench_compare(LMS_SHA256_N32_H15, LMOTS_SHA256_N32_W4, 15u, 16384u, 8u);

    printf("--- (2) cache scaling across subtree boundary (q=32 for j=5) ---\n\n");
    /* H10: across the q=32 boundary (bottom subtree has 32 leaves), to observe rebuild amortization. */
    bench_cache_scaling(LMS_SHA256_N32_H10, LMOTS_SHA256_N32_W4, 10u, 16384u,
                        scaling_counts, sizeof(scaling_counts) / sizeof(scaling_counts[0]));

    printf("Done.\n");
    return 0;
}
