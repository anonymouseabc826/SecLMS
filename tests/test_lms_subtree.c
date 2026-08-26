/* LMS tree-layer co-design (phase 2): configurator + data structures + tree build / auth path + incremental build tests.
 *
 * Validates the lms_subtree module:
 *   1. Memory estimation: lms_tree_estimate_memory against hand-derived expected values (oracle, independent recomputation).
 *   2. Configurator selection: j / sublevels / fit for H5/H20 under different memory_target values.
 *   3. updates propagation formulas: several known points aligned with hash-sigs semantics.
 *   4. ctx lifecycle: allocator injection (counting allocator), geometry relations, budget match, no leaks, failure rollback.
 *   5. ACTIVE tree build + auth-path lookup (H5 full-tree special case): compared against lms_tree_node / lms_public_key_generate.
 *   6. Incremental build primitive lms_tree_add_next_node (H15 multi-sublevel): streaming build compared against lms_tree_node.
 *
 * Hand-derived oracle (unified convention: est = actual allocation, nodes+stack, nodes includes the index-0 empty slot):
 *   Each sublevel s (sub_h = (s<sublevels-1)? j : top, top=h-(sublevels-1)*j):
 *     ACTIVE: nodes=2^(sub_h+1)*n (1-based indexing includes the index-0 empty slot) + stack=sub_h*n
 *     UPCOMING (only when s<sublevels-1): same as ACTIVE. No UPCOMING at the top level.
 *   Memory = sum_s [ACTIVE + (s<sublevels-1 ? UPCOMING : 0)], sublevels=ceil(h/j).
 *
 *   Worked examples (n=32):
 *   - h=5, j=5: sublevels=1, top=5 -> ACTIVE nodes=32*(2^6)=2048 + stack=5*32=160 -> 2208.
 *   - h=5, j=2: sublevels=3, top=1
 *       s0(sub_h=2): ACTIVE nodes 32*8=256+stack 64=320, UPCOMING 320 -> 640
 *       s1(sub_h=2): 640
 *       s2(sub_h=1): ACTIVE nodes 32*4=128+stack 32=160 (no UPCOMING)
 *       total 640+640+160 = 1440.
 *   - h=20, j=5: sublevels=4, top=5
 *       Each sub_h=5 subtree nodes=32*64=2048 + stack=160 = 2208;
 *       s0,s1,s2 each ACTIVE+UPCOMING=4416, s3 ACTIVE only=2208;
 *       total 3*4416+2208 = 13248+2208 = 15456.
 *   - h=20, j=2: sublevels=10, top=2
 *       Each sub_h=2 subtree nodes 32*8=256+stack 64=320; s0..s8 each 640, s9(sub_h=2) ACTIVE only=320;
 *       total 9*640+320 = 5760+320 = 6080.
 *
 *   Configurator inference (n=32):
 *   - H5, target=2300: j=5 (2208<=2300, sub=1) selected; j=4 (2464>2300) over budget -> pick j=5. fit=WITHIN, sub=1, est=2208.
 *   - H5, target=1000: all over budget (smallest j=2 gives 1440>1000) -> pick minimum-memory j=2. fit=OVERBUDGET, est=1440.
 *   - H20, target=16384: j=5 (15456<=16384, sub=4) fastest feasible; j=4 (10368, sub=5) slower -> pick j=5. fit=WITHIN, est=15456.
 *   - H20, target=2000: all over budget (smallest j=2 gives 6080>2000) -> pick minimum-memory j=2. fit=OVERBUDGET, est=6080.
 */

#include "../src/lms_internal.h"
#include "../src/lms_subtree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

static void expect_u64(uint64_t actual, uint64_t expected, const char *label)
{
    if (actual != expected) {
        printf("FAIL: %s expected %llu, got %llu\n", label,
               (unsigned long long)expected, (unsigned long long)actual);
        g_failures++;
    }
}

static void expect_u32(uint32_t actual, uint32_t expected, const char *label)
{
    if (actual != expected) {
        printf("FAIL: %s expected %u, got %u\n", label, expected, actual);
        g_failures++;
    }
}

static void expect_status(int actual, int expected, const char *label)
{
    if (actual != expected) {
        printf("FAIL: %s expected %d, got %d\n", label, expected, actual);
        g_failures++;
    }
}

/* Independent oracle: does not reuse the code under test; recomputes memory with the hand-derived formula from the header comment (unified convention, nodes includes the index-0 empty slot). */
static uint64_t oracle_memory(uint32_t h, uint32_t j, uint32_t n)
{
    uint32_t sublevels = (h + j - 1u) / j;
    uint32_t top = h - (sublevels - 1u) * j;
    uint64_t mem = 0u;
    uint32_t s;
    for (s = 0; s < sublevels; s++) {
        uint32_t sub_h = (s + 1u < sublevels) ? j : top;
        uint64_t per = ((uint64_t)2u << sub_h) * n + (uint64_t)sub_h * n; /* nodes (2^(sub_h+1) slots) + stack */
        mem += per;                          /* ACTIVE */
        if (s + 1u < sublevels) {
            mem += per;                      /* UPCOMING (non-top level) */
        }
    }
    return mem;
}

static void test_estimate_memory(void)
{
    uint32_t sublevels = 0u;

    expect_u64(lms_tree_estimate_memory(5u, 5u, 32u, &sublevels), 2208u, "est h5 j5");
    expect_u32(sublevels, 1u, "est h5 j5 sublevels");

    expect_u64(lms_tree_estimate_memory(5u, 2u, 32u, &sublevels), 1440u, "est h5 j2");
    expect_u32(sublevels, 3u, "est h5 j2 sublevels");

    expect_u64(lms_tree_estimate_memory(20u, 5u, 32u, &sublevels), 15456u, "est h20 j5");
    expect_u32(sublevels, 4u, "est h20 j5 sublevels");

    expect_u64(lms_tree_estimate_memory(20u, 2u, 32u, &sublevels), 6080u, "est h20 j2");
    expect_u32(sublevels, 10u, "est h20 j2 sublevels");

    /* Oracle cross-check: covers several (h,j) combinations to confirm the implementation matches the independent formula. */
    {
        uint32_t hs[] = {5u, 10u, 15u, 20u, 25u};
        size_t hi;
        for (hi = 0; hi < sizeof(hs) / sizeof(hs[0]); hi++) {
            uint32_t h = hs[hi];
            uint32_t j;
            for (j = 2u; j <= h; j++) {
                char label[64];
                snprintf(label, sizeof(label), "oracle h%u j%u", h, j);
                expect_u64(lms_tree_estimate_memory(h, j, 32u, NULL),
                           oracle_memory(h, j, 32u), label);
            }
        }
    }
}

static void test_configure_within_budget(void)
{
    lms_tree_config_t cfg;

    /* H5 / ample budget (2300): pick j=h=5 (full-tree special case), sublevels=1. */
    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 2300u, &cfg), LMS_OK,
                  "cfg h5 2300 status");
    expect_u32(cfg.subtree_size, 5u, "cfg h5 2300 j");
    expect_u32(cfg.sublevels, 1u, "cfg h5 2300 sublevels");
    expect_u64(cfg.est_memory, 2208u, "cfg h5 2300 est");
    expect_u32((uint32_t)cfg.fit, (uint32_t)LMS_TREE_FIT_WITHIN_BUDGET, "cfg h5 2300 fit");
    expect_u32(cfg.height, 5u, "cfg h5 height");

    /* H20 / ~16KiB budget: pick j=5 (fastest feasible tier, sublevels=4). */
    expect_status(lms_tree_configure(LMS_SHA256_N32_H20, 16384u, &cfg), LMS_OK,
                  "cfg h20 16384 status");
    expect_u32(cfg.subtree_size, 5u, "cfg h20 16384 j");
    expect_u32(cfg.sublevels, 4u, "cfg h20 16384 sublevels");
    expect_u64(cfg.est_memory, 15456u, "cfg h20 16384 est");
    expect_u32((uint32_t)cfg.fit, (uint32_t)LMS_TREE_FIT_WITHIN_BUDGET, "cfg h20 16384 fit");
}

static void test_configure_overbudget(void)
{
    lms_tree_config_t cfg;

    /* H5 / budget too small (1000): every j over budget, take the minimum-memory tier j=2 (1440). */
    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 1000u, &cfg), LMS_OK,
                  "cfg h5 1000 status");
    expect_u32(cfg.subtree_size, 2u, "cfg h5 1000 j");
    expect_u32(cfg.sublevels, 3u, "cfg h5 1000 sublevels");
    expect_u64(cfg.est_memory, 1440u, "cfg h5 1000 est");
    expect_u32((uint32_t)cfg.fit, (uint32_t)LMS_TREE_FIT_OVERBUDGET, "cfg h5 1000 fit");

    /* H20 / tiny budget (2000): all over budget, take the minimum-memory tier j=2 (6080). */
    expect_status(lms_tree_configure(LMS_SHA256_N32_H20, 2000u, &cfg), LMS_OK,
                  "cfg h20 2000 status");
    expect_u32(cfg.subtree_size, 2u, "cfg h20 2000 j");
    expect_u64(cfg.est_memory, 6080u, "cfg h20 2000 est");
    expect_u32((uint32_t)cfg.fit, (uint32_t)LMS_TREE_FIT_OVERBUDGET, "cfg h20 2000 fit");
}

static void test_updates_formulas(void)
{
    /* generated: height<=subtree -> 2^height. */
    expect_u64(lms_tree_updates_generated(5u, 5u), 32u, "upd gen h5 j5");
    expect_u64(lms_tree_updates_generated(3u, 5u), 8u, "upd gen h3 j5");
    /* generated: height>subtree -> 2^((sublevels-1)*subtree). h=20,j=5: sub=4 -> 2^15. */
    expect_u64(lms_tree_updates_generated(20u, 5u), 32768u, "upd gen h20 j5");
    /* required: sublevels+1. h=20,j=5: sub=4 -> 5; h=5,j=5: sub=1 -> 2. */
    expect_u64(lms_tree_updates_required(20u, 5u), 5u, "upd req h20 j5");
    expect_u64(lms_tree_updates_required(5u, 5u), 2u, "upd req h5 j5");
    /* Propagation constraint example (only meaningful for multi-level): with j=5, generated>=required always holds (>=32). */
    expect_u64(lms_tree_updates_generated(20u, 5u) >= lms_tree_updates_required(20u, 5u),
               1u, "upd h20 j5 propagates");
}

static void test_invalid_input(void)
{
    lms_tree_config_t cfg;

    expect_status(lms_tree_configure(0xdeadbeefu, 16384u, &cfg), LMS_ERR_INVALID,
                  "cfg bad type");
    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 16384u, NULL), LMS_ERR_INVALID,
                  "cfg null config");
}

/* ---- Allocator injection + ctx lifecycle (design doc sec. 8 step 2) ---- */

/* Counting allocator: tracks allocation/free counts and byte totals through the injected callbacks (validates injection points + no leaks + budget match). */
typedef struct {
    uint32_t alloc_calls;
    uint32_t free_calls;
    uint64_t alloc_bytes;     /* cumulative allocated bytes (not reduced by frees, for checking totals) */
    uint64_t live_bytes;      /* currently live bytes (decremented on free, should return to 0) */
    uint32_t fail_after;      /* allocations after the fail_after-th return NULL (injected allocation failure); 0=never fail */
} counting_alloc_t;

static void *counting_alloc(void *context, size_t size)
{
    counting_alloc_t *ca = (counting_alloc_t *)context;
    /* Allocate an extra sizeof(size_t) header to record the block size, used to decrement live_bytes on free. */
    size_t *block;
    ca->alloc_calls++;
    if (ca->fail_after != 0u && ca->alloc_calls > ca->fail_after) {
        return NULL;
    }
    block = (size_t *)malloc(size + sizeof(size_t));
    if (block == NULL) {
        return NULL;
    }
    block[0] = size;
    ca->alloc_bytes += size;
    ca->live_bytes += size;
    return (void *)(block + 1);
}

static void counting_free(void *context, void *ptr)
{
    counting_alloc_t *ca = (counting_alloc_t *)context;
    size_t *block;
    if (ptr == NULL) {
        return;
    }
    block = ((size_t *)ptr) - 1;
    ca->free_calls++;
    ca->live_bytes -= block[0];
    free(block);
}

static void test_ctx_lifecycle(void)
{
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t I[LMS_I_LEN];
    uint64_t data_bytes;

    memset(&ca, 0, sizeof(ca));
    memset(I, 0xA5, sizeof(I));

    /* H5 / j=5 (full-tree special case): sublevels=1, single top-level subtree, no UPCOMING. */
    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 2300u, &cfg), LMS_OK, "ctx cfg h5");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "ctx init h5");
    expect_u32(ctx.sublevels, 1u, "ctx h5 sublevels");
    expect_u32(ctx.top_subtree_size, 5u, "ctx h5 top");
    expect_u32(ctx.levels[0].active.height, 5u, "ctx h5 active.height");
    expect_u32(ctx.levels[0].active.level, 5u, "ctx h5 active.level(root)");
    expect_u32(ctx.levels[0].active.levels_below, 0u, "ctx h5 active.levels_below");
    expect_u32((uint32_t)ctx.levels[0].has_upcoming, 0u, "ctx h5 has_upcoming=0");

    /* Budget match: allocated_bytes = est_memory (data) + sublevels*sizeof(sublevel) (structure). */
    data_bytes = lms_tree_ctx_allocated_bytes(&ctx) - (uint64_t)ctx.sublevels * sizeof(lms_sublevel_t);
    expect_u64(data_bytes, cfg.est_memory, "ctx h5 est==allocated(data)");
    /* Injection active: allocation really went through the injected allocator, and allocated bytes == allocated_bytes. */
    expect_u64(ca.alloc_bytes, lms_tree_ctx_allocated_bytes(&ctx), "ctx h5 alloc_bytes==allocated");
    if (ca.alloc_calls == 0u) {
        printf("FAIL: ctx h5 allocator not injected (alloc_calls=0)\n");
        g_failures++;
    }
    /* K_q source defaults to NULL (falls back to lmots_public_from_private during tree build). */
    if (ctx.ots_pub != NULL) {
        printf("FAIL: ctx h5 ots_pub expected NULL\n");
        g_failures++;
    }

    lms_tree_ctx_free(&ctx);
    /* No leaks: allocation count == free count, live bytes back to 0. */
    expect_u32(ca.alloc_calls, ca.free_calls, "ctx h5 alloc==free calls");
    expect_u64(ca.live_bytes, 0u, "ctx h5 live_bytes==0 after free");

    /* H20 / j=5: sublevels=4, geometry relations (level/levels_below/top) + UPCOMING presence. */
    memset(&ca, 0, sizeof(ca));
    expect_status(lms_tree_configure(LMS_SHA256_N32_H20, 16384u, &cfg), LMS_OK, "ctx cfg h20");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "ctx init h20");
    expect_u32(ctx.sublevels, 4u, "ctx h20 sublevels");
    expect_u32(ctx.top_subtree_size, 5u, "ctx h20 top");
    /* Geometry: s0{h5,root5,below0} s1{h5,root10,below5} s2{h5,root15,below10} s3{h5,root20,below15} */
    expect_u32(ctx.levels[0].active.level, 5u, "ctx h20 s0 root_level");
    expect_u32(ctx.levels[0].active.levels_below, 0u, "ctx h20 s0 below");
    expect_u32(ctx.levels[1].active.level, 10u, "ctx h20 s1 root_level");
    expect_u32(ctx.levels[1].active.levels_below, 5u, "ctx h20 s1 below");
    expect_u32(ctx.levels[3].active.level, 20u, "ctx h20 s3 root_level(=h)");
    expect_u32(ctx.levels[3].active.levels_below, 15u, "ctx h20 s3 below");
    /* UPCOMING: s0..s2 have it, s3 (top level) does not. */
    expect_u32((uint32_t)ctx.levels[0].has_upcoming, 1u, "ctx h20 s0 has_upcoming");
    expect_u32((uint32_t)ctx.levels[2].has_upcoming, 1u, "ctx h20 s2 has_upcoming");
    expect_u32((uint32_t)ctx.levels[3].has_upcoming, 0u, "ctx h20 s3(top) has_upcoming=0");
    /* Budget match + injection. */
    data_bytes = lms_tree_ctx_allocated_bytes(&ctx) - (uint64_t)ctx.sublevels * sizeof(lms_sublevel_t);
    expect_u64(data_bytes, cfg.est_memory, "ctx h20 est==allocated(data)");
    expect_u64(ca.alloc_bytes, lms_tree_ctx_allocated_bytes(&ctx), "ctx h20 alloc_bytes==allocated");
    lms_tree_ctx_free(&ctx);
    expect_u32(ca.alloc_calls, ca.free_calls, "ctx h20 alloc==free calls");
    expect_u64(ca.live_bytes, 0u, "ctx h20 live_bytes==0 after free");
}

static void test_ctx_alloc_failure_rollback(void)
{
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t I[LMS_I_LEN];

    memset(I, 0x5A, sizeof(I));
    expect_status(lms_tree_configure(LMS_SHA256_N32_H20, 16384u, &cfg), LMS_OK, "rb cfg h20");

    /* Inject "fail from the 4th allocation on": init must roll back the allocated buffers, return an error, and leak nothing. */
    memset(&ca, 0, sizeof(ca));
    ca.fail_after = 3u;
    expect_status(lms_tree_ctx_init(&ctx, &cfg, I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_ERR_INVALID, "rb init fails");
    expect_u64(ca.live_bytes, 0u, "rb live_bytes==0 (rollback clean)");
    /* Everything already allocated (first 3 succeeded) must all be rolled back and freed. */
    expect_u32(ca.alloc_calls, ca.free_calls + 1u, "rb alloc==free+failed_attempt");
}

static void test_ctx_invalid_args(void)
{
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t I[LMS_I_LEN];

    memset(&ca, 0, sizeof(ca));
    memset(I, 0, sizeof(I));
    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 2300u, &cfg), LMS_OK, "inv cfg");

    expect_status(lms_tree_ctx_init(NULL, &cfg, I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_ERR_INVALID, "inv null ctx");
    expect_status(lms_tree_ctx_init(&ctx, NULL, I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_ERR_INVALID, "inv null config");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, NULL, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_ERR_INVALID, "inv null I");
    /* alloc/free must be non-NULL (this module never calls malloc directly). */
    expect_status(lms_tree_ctx_init(&ctx, &cfg, I, NULL, NULL,
                                    NULL, counting_free, &ca),
                  LMS_ERR_INVALID, "inv null alloc");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, I, NULL, NULL,
                                    counting_alloc, NULL, &ca),
                  LMS_ERR_INVALID, "inv null free");
}

/* ---- ACTIVE tree build + auth-path lookup (design doc sec. 8 step 3, H5 full-tree special case) ---- */

static void make_key_h5(lms_private_key_t *priv, uint8_t seed_tag)
{
    uint8_t I[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];
    uint32_t i;
    for (i = 0; i < LMS_I_LEN; i++) {
        I[i] = (uint8_t)(0x10u + i);
    }
    for (i = 0; i < LMS_SEED_LEN; i++) {
        seed[i] = (uint8_t)(seed_tag + i);
    }
    lms_private_key_init(priv, LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4, I, seed);
}

static void expect_bytes_eq(const uint8_t *actual, const uint8_t *expected,
                            size_t len, const char *label)
{
    if (memcmp(actual, expected, len) != 0) {
        printf("FAIL: %s mismatch\n", label);
        g_failures++;
    }
}

/* H5 (j=h=5, sublevels=1) build: root/nodes/auth path are byte-identical to the reference. */
static void test_build_active_h5(void)
{
    lms_private_key_t priv;
    lms_public_key_t pub;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t root[LMS_N];
    uint8_t node_ref[LMS_N];
    uint8_t node_sub[LMS_N];
    uint8_t path[LMS_MAX_HEIGHT * LMS_N];
    uint32_t i;

    memset(&ca, 0, sizeof(ca));
    make_key_h5(&priv, 0x00u);
    expect_status(lms_public_key_generate(&priv, &pub), LMS_OK, "ref keygen");

    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 2300u, &cfg), LMS_OK, "build cfg h5");
    expect_u32(cfg.sublevels, 1u, "build cfg h5 sublevels==1");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "build ctx init");

    expect_status(lms_tree_build_active(&ctx, &priv), LMS_OK, "build active h5");
    expect_status(lms_tree_root(&ctx, root), LMS_OK, "build root h5");
    expect_bytes_eq(root, pub.root, LMS_N, "build root == reference root");

    /* Spot-check nodes (leaf/internal/root): the sole ACTIVE subtree is the whole tree, so local==whole-tree node number. */
    {
        static const uint32_t probes[] = {1u, 2u, 3u, 5u, 16u, 17u, 31u, 32u, 33u, 47u, 63u};
        const lms_subtree_t *t = &ctx.levels[0].active;
        for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            expect_status(lms_tree_node(&priv, probes[i], node_ref), LMS_OK, "ref tree node");
            memcpy(node_sub, t->nodes + (size_t)probes[i] * ctx.n, LMS_N);
            expect_bytes_eq(node_sub, node_ref, LMS_N, "node parity");
        }
    }

    /* Auth path (q=7) matches reference siblings level by level (RFC 8554 order, leaf to root). */
    expect_status(lms_tree_auth_path(&ctx, 7u, path), LMS_OK, "auth path h5");
    {
        uint32_t node_num = (1u << ctx.height) + 7u;
        for (i = 0; i < ctx.height; i++) {
            uint32_t sibling = node_num ^ 1u;
            expect_status(lms_tree_node(&priv, sibling, node_ref), LMS_OK, "ref sibling");
            expect_bytes_eq(path + (size_t)i * LMS_N, node_ref, LMS_N, "auth sibling parity");
            node_num /= 2u;
        }
    }

    /* Auth-path spot-check across q (q=0 boundary and q=31 last leaf). */
    {
        uint32_t q;
        for (q = 0u; q < 32u; q += 31u) { /* q=0 and q=31 */
            uint32_t node_num;
            expect_status(lms_tree_auth_path(&ctx, q, path), LMS_OK, "auth path q boundary");
            node_num = (1u << ctx.height) + q;
            for (i = 0; i < ctx.height; i++) {
                uint32_t sibling = node_num ^ 1u;
                expect_status(lms_tree_node(&priv, sibling, node_ref), LMS_OK, "ref sibling b");
                expect_bytes_eq(path + (size_t)i * LMS_N, node_ref, LMS_N, "auth parity b");
                node_num /= 2u;
            }
        }
    }

    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "build h5 no leak");
}

/* Multi-sublevel (j<h) build_active is explicitly unsupported at this step: returns LMS_ERR_INVALID. */
static void test_build_active_multisublevel_unsupported(void)
{
    lms_private_key_t priv;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;

    memset(&ca, 0, sizeof(ca));
    /* H20 / j=5 -> sublevels=4 (multi-sublevel). ctx can build the skeleton, but build_active is unsupported. */
    expect_status(lms_tree_configure(LMS_SHA256_N32_H20, 16384u, &cfg), LMS_OK, "ms cfg h20");
    expect_u32(cfg.sublevels, 4u, "ms cfg h20 sublevels==4");
    {
        uint8_t I[LMS_I_LEN];
        uint8_t seed[LMS_SEED_LEN];
        uint32_t i;
        for (i = 0; i < LMS_I_LEN; i++) I[i] = (uint8_t)(0x20u + i);
        for (i = 0; i < LMS_SEED_LEN; i++) seed[i] = (uint8_t)(0x40u + i);
        lms_private_key_init(&priv, LMS_SHA256_N32_H20, LMOTS_SHA256_N32_W4, I, seed);
        expect_status(lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                                        counting_alloc, counting_free, &ca),
                      LMS_OK, "ms ctx init");
        expect_status(lms_tree_build_active(&ctx, &priv), LMS_ERR_INVALID,
                      "ms build_active unsupported (sublevels>1)");
        lms_tree_ctx_free(&ctx);
    }
    expect_u64(ca.live_bytes, 0u, "ms no leak");
}

/* ---- Incremental build primitive (design doc sec. 8 step 4, H15 multi-sublevel) ----
 *
 * Uses lms_tree_add_next_node to stream-build one bottom-level subtree leaf by leaf
 * (H15 / j=5 -> bottom subtree height 5, 32 leaves); its root and all nodes are
 * compared against the lms_tree_node oracle (byte by byte). Validates stack-merge logic.
 */
static void test_add_next_node_h15_subtree(void)
{
    lms_private_key_t priv;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t leaf[LMS_N];
    uint8_t node_ref[LMS_N];
    lms_subtree_t *sub;
    uint32_t q;
    uint32_t i;
    int done = 0;

    memset(&ca, 0, sizeof(ca));
    /* H15 private key: configure j=5 -> sublevels=3 (multi-sublevel), bottom ACTIVE subtree height 5. */
    {
        uint8_t I[LMS_I_LEN];
        uint8_t seed[LMS_SEED_LEN];
        for (i = 0; i < LMS_I_LEN; i++) I[i] = (uint8_t)(0x30u + i);
        for (i = 0; i < LMS_SEED_LEN; i++) seed[i] = (uint8_t)(0x50u + i);
        lms_private_key_init(&priv, LMS_SHA256_N32_H15, LMOTS_SHA256_N32_W4, I, seed);
    }
    expect_status(lms_tree_configure(LMS_SHA256_N32_H15, 16384u, &cfg), LMS_OK, "inc cfg h15");
    expect_u32(cfg.sublevels, 3u, "inc cfg h15 sublevels==3");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "inc ctx init");

    /* Stream-build using the bottom ACTIVE subtree (sublevel 0, height 5, 32 leaves, covering real leaves q=0..31). */
    sub = &ctx.levels[0].active;
    expect_u32(sub->height, 5u, "inc sub height==5");
    expect_u32(sub->level, 5u, "inc sub root_level==5");
    expect_u64(sub->left_leaf, 0u, "inc sub left_leaf==0");

    for (q = 0u; q < 32u; q++) {
        /* Leaf value = D_LEAF output: the real leaf value is obtained via the default K_q source (lmots_public_from_private) + lms_tree_node. */
        uint32_t leaf_node_num = (1u << ctx.height) + q; /* whole-tree leaf node number */
        expect_status(lms_tree_node(&priv, leaf_node_num, leaf), LMS_OK, "inc ref leaf");
        done = lms_tree_add_next_node(sub, leaf, ctx.I, ctx.hash_alg, ctx.n);
        if (q < 31u) {
            expect_status(done, 0, "inc add not done yet");
        } else {
            expect_status(done, 1, "inc add done at last leaf");
        }
    }
    expect_u64(sub->current_index, 32u, "inc current_index==32");

    /* The built subtree (covering whole-tree nodes [32..47]: level-5 root + internals + leaves)
     * is byte-identical to lms_tree_node.
     * Subtree local index -> whole-tree node number: with sub_h=5, root_level=5, left_leaf=0,
     * local maps to the low 5-bit segment of the whole-tree number (this subtree covers the
     * leftmost segment of whole-tree levels 0..5). The root is checked via the subtree mapping. */
    {
        /* Subtree root local=1, corresponding to whole-tree level-5 node 0 = number 2^(15-5)+0 = 1024. */
        expect_status(lms_tree_node(&priv, 1024u, node_ref), LMS_OK, "inc ref root");
        expect_bytes_eq(sub->nodes + (size_t)1u * ctx.n, node_ref, LMS_N, "inc subtree root parity");

        /* Spot-check internal and leaf nodes: local -> whole-tree number via the subtree mapping.
         * local=4 (subtree level-3 node 0, depth d=2) -> whole-tree level-3 node 0 = 2^(15-3)+0=4096; local=32 (leaf 0) -> 2^15+0=32768. */
        expect_status(lms_tree_node(&priv, 4096u, node_ref), LMS_OK, "inc ref node L3");
        expect_bytes_eq(sub->nodes + (size_t)4u * ctx.n, node_ref, LMS_N, "inc node L3 parity");
        expect_status(lms_tree_node(&priv, 32768u, node_ref), LMS_OK, "inc ref leaf0");
        expect_bytes_eq(sub->nodes + (size_t)32u * ctx.n, node_ref, LMS_N, "inc leaf0 parity");
        expect_status(lms_tree_node(&priv, 32768u + 31u, node_ref), LMS_OK, "inc ref leaf31");
        expect_bytes_eq(sub->nodes + (size_t)63u * ctx.n, node_ref, LMS_N, "inc leaf31 parity");
    }

    /* Adding a node after the subtree is complete must fail. */
    expect_status(lms_tree_add_next_node(sub, leaf, ctx.I, ctx.hash_alg, ctx.n),
                  LMS_ERR_INVALID, "inc add after done rejected");

    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "inc h15 no leak");
}

/* ---- Step 4 phase B: KeyGen streaming root + ACTIVE/UPCOMING sign cache (H15 j=5, sublevels=3) ----
 *
 * H15 subtree geometry (j=5, sublevels=3, top=5):
 *   sublevel0 height 5 covers real leaves (32 real leaves each, 1024 in the whole tree);
 *   sublevel1 height 5, leaves = level-5 nodes (32 each, 32 in the whole tree);
 *   sublevel2 height 5, leaves = level-10 nodes (1 -> whole-tree root).
 * oracle: root compared against lms_public_key_generate; auth-path siblings compared
 *   level by level against lms_tree_node.
 * Verification stops at H15 (32768 leaves: computable on a PC, tens of seconds acceptable).
 */

/* Builds the H15 private key (same deterministic seed as test_add_next_node_h15_subtree, for easy recomputation). */
static void make_key_h15(lms_private_key_t *priv)
{
    uint8_t I[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];
    uint32_t i;
    for (i = 0; i < LMS_I_LEN; i++) I[i] = (uint8_t)(0x30u + i);
    for (i = 0; i < LMS_SEED_LEN; i++) seed[i] = (uint8_t)(0x50u + i);
    lms_private_key_init(priv, LMS_SHA256_N32_H15, LMOTS_SHA256_N32_W4, I, seed);
}

/* oracle: computes the auth path of leaf q level by level with lms_tree_node (h siblings, leaf to root). */
static void oracle_auth_path(const lms_private_key_t *priv, uint32_t h, uint32_t q,
                             uint8_t *path)
{
    uint32_t node_num = (1u << h) + q;
    uint32_t i;
    for (i = 0; i < h; i++) {
        uint32_t sibling = node_num ^ 1u;
        lms_tree_node(priv, sibling, path + (size_t)i * LMS_N);
        node_num /= 2u;
    }
}

/* keygen_root output compared against lms_public_key_generate. */
static void test_keygen_root_h15(void)
{
    lms_private_key_t priv;
    lms_public_key_t pub;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t root[LMS_N];

    memset(&ca, 0, sizeof(ca));
    make_key_h15(&priv);
    expect_status(lms_public_key_generate(&priv, &pub), LMS_OK, "kg ref keygen");

    expect_status(lms_tree_configure(LMS_SHA256_N32_H15, 16384u, &cfg), LMS_OK, "kg cfg h15");
    expect_u32(cfg.sublevels, 3u, "kg cfg h15 sublevels==3");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "kg ctx init");

    expect_status(lms_tree_keygen_root(&ctx, &priv, root), LMS_OK, "kg keygen_root");
    expect_bytes_eq(root, pub.root, LMS_N, "kg root == reference pub.root");

    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "kg no leak");
}

/* After sign_init, auth paths for q=0 and for q inside each ACTIVE coverage range are compared against the oracle (no rotation). */
static void test_sign_init_auth_path_h15(void)
{
    lms_private_key_t priv;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t path[LMS_MAX_HEIGHT * LMS_N];
    uint8_t ref[LMS_MAX_HEIGHT * LMS_N];
    static const uint32_t qs[] = {0u, 1u, 5u, 31u}; /* bottom ACTIVE covers [0,32) */
    uint32_t i;

    memset(&ca, 0, sizeof(ca));
    make_key_h15(&priv);
    expect_status(lms_tree_configure(LMS_SHA256_N32_H15, 16384u, &cfg), LMS_OK, "si cfg h15");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "si ctx init");

    expect_status(lms_tree_sign_init(&ctx, &priv), LMS_OK, "si sign_init");

    for (i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
        uint32_t q = qs[i];
        expect_status(lms_tree_sign_auth_path(&ctx, q, path), LMS_OK, "si auth_path");
        oracle_auth_path(&priv, ctx.height, q, ref);
        expect_bytes_eq(path, ref, (size_t)ctx.height * LMS_N, "si auth_path == oracle");
    }

    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "si no leak");
}

/* sign_advance rotation correctness: auth paths stay correct as q crosses bottom/middle subtree boundaries.
 * Covers: bottom rotation points (32/64/33), middle rotation point (1024=32*32, triggers sublevel1 rotation),
 * plus 1025/1056 etc. For each q, sign_advance then sign_auth_path, compared against the oracle. */
static void test_sign_advance_rotation_h15(void)
{
    lms_private_key_t priv;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    uint8_t path[LMS_MAX_HEIGHT * LMS_N];
    uint8_t ref[LMS_MAX_HEIGHT * LMS_N];
    /* Boundary points: 32/64 adjacent bottom segments; 1024 triggers sublevel1 rotation (32 bottom subtrees = 1024 leaves). */
    static const uint32_t qs[] = {0u, 31u, 32u, 33u, 63u, 64u, 96u, 100u,
                                  1023u, 1024u, 1025u, 1055u, 1056u, 2048u};
    uint32_t i;

    memset(&ca, 0, sizeof(ca));
    make_key_h15(&priv);
    expect_status(lms_tree_configure(LMS_SHA256_N32_H15, 16384u, &cfg), LMS_OK, "adv cfg h15");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, priv.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "adv ctx init");
    expect_status(lms_tree_sign_init(&ctx, &priv), LMS_OK, "adv sign_init");

    for (i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
        uint32_t q = qs[i];
        char label[64];
        snprintf(label, sizeof(label), "adv q=%u", q);
        expect_status(lms_tree_sign_advance(&ctx, &priv, q), LMS_OK, "adv advance");
        expect_status(lms_tree_sign_auth_path(&ctx, q, path), LMS_OK, "adv auth_path");
        oracle_auth_path(&priv, ctx.height, q, ref);
        if (memcmp(path, ref, (size_t)ctx.height * LMS_N) != 0) {
            printf("FAIL: %s auth_path != oracle after advance\n", label);
            g_failures++;
        }
    }

    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "adv no leak");
}

/* ---- Design doc step 5: lms_sign auth-path backend integration ----
 *
 * After registering the lms_subtree backend, lms_sign's output signatures must be
 * byte-identical to the default (lms_tree_node recursion), and lms_verify must pass.
 * Covers H5 (sublevels=1, fast) and H15 (multi-sublevel, across subtree boundaries).
 * Validates backend register/unregister semantics: default path untouched, cache used after registration.
 */

/* Build two private-key copies from the same (I,seed): privA uses default recursion, privB the backend cache.
 * Their q counters advance independently; signatures at the same q must be byte-identical. */
static void test_sign_backend_h5(void)
{
    lms_private_key_t privA;
    lms_private_key_t privB;
    lms_public_key_t pub;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    static const uint8_t msg[] = "lms-subtree auth-path backend";
    uint8_t sigA[LMS_MAX_SIGNATURE_LEN];
    uint8_t sigB[LMS_MAX_SIGNATURE_LEN];
    size_t lenA = 0u;
    size_t lenB = 0u;
    uint32_t trial;

    memset(&ca, 0, sizeof(ca));
    make_key_h5(&privA, 0x00u);
    make_key_h5(&privB, 0x00u); /* same (I,seed), same root */
    expect_status(lms_public_key_generate(&privA, &pub), LMS_OK, "sb ref keygen");

    expect_status(lms_tree_configure(LMS_SHA256_N32_H5, 2300u, &cfg), LMS_OK, "sb cfg h5");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, privB.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "sb ctx init");
    expect_status(lms_tree_sign_init(&ctx, &privB), LMS_OK, "sb sign_init");

    /* Register the backend (context=ctx). After this, privB's lms_sign uses the cached lookup. */
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &ctx);

    /* Sign q=0..7 consecutively: privA default recursion vs privB backend, byte-identical + verify passes. */
    for (trial = 0u; trial < 8u; trial++) {
        expect_status(lms_sign(&privA, msg, sizeof(msg), sigA, sizeof(sigA), &lenA),
                      LMS_OK, "sb sign A (default)");
        expect_status(lms_sign(&privB, msg, sizeof(msg), sigB, sizeof(sigB), &lenB),
                      LMS_OK, "sb sign B (backend)");
        expect_u64((uint64_t)lenA, (uint64_t)lenB, "sb sig len equal");
        if (lenA == lenB) {
            expect_bytes_eq(sigB, sigA, lenA, "sb signature byte-identical");
        }
        expect_status(lms_verify(&pub, msg, sizeof(msg), sigB, lenB), LMS_OK,
                      "sb verify backend sig");
    }

    /* Unregister, fall back to default: privB's next signature must match privA (also fallback/default). */
    lms_auth_path_backend_set(NULL, NULL);
    expect_status(lms_sign(&privA, msg, sizeof(msg), sigA, sizeof(sigA), &lenA),
                  LMS_OK, "sb sign A2 (default)");
    expect_status(lms_sign(&privB, msg, sizeof(msg), sigB, sizeof(sigB), &lenB),
                  LMS_OK, "sb sign B2 (after unset)");
    if (lenA == lenB) {
        expect_bytes_eq(sigB, sigA, lenA, "sb sig identical after unset");
    }

    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "sb h5 no leak");
}

/* H15: backend signatures at cross-subtree-boundary q values are byte-identical to default recursion. */
static void test_sign_backend_h15(void)
{
    lms_private_key_t privA;
    lms_private_key_t privB;
    lms_public_key_t pub;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    counting_alloc_t ca;
    static const uint8_t msg[] = "h15 backend boundary";
    uint8_t sigA[LMS_MAX_SIGNATURE_LEN];
    uint8_t sigB[LMS_MAX_SIGNATURE_LEN];
    size_t lenA = 0u;
    size_t lenB = 0u;
    /* Boundary q values: 31/32 (bottom), 1023/1024 (middle). priv->q positions directly to the leaf being signed. */
    static const uint32_t qs[] = {0u, 31u, 32u, 1023u, 1024u};
    uint32_t i;

    memset(&ca, 0, sizeof(ca));
    make_key_h15(&privA);
    make_key_h15(&privB);
    expect_status(lms_public_key_generate(&privA, &pub), LMS_OK, "sb15 ref keygen");

    expect_status(lms_tree_configure(LMS_SHA256_N32_H15, 16384u, &cfg), LMS_OK, "sb15 cfg");
    expect_status(lms_tree_ctx_init(&ctx, &cfg, privB.I, NULL, NULL,
                                    counting_alloc, counting_free, &ca),
                  LMS_OK, "sb15 ctx init");
    expect_status(lms_tree_sign_init(&ctx, &privB), LMS_OK, "sb15 sign_init");
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &ctx);

    for (i = 0u; i < sizeof(qs) / sizeof(qs[0]); i++) {
        uint32_t q = qs[i];
        char label[64];
        snprintf(label, sizeof(label), "sb15 q=%u", q);
        /* Both copies sign the same q (lms_sign uses priv->q and increments after signing). */
        privA.q = q;
        privB.q = q;
        expect_status(lms_sign(&privA, msg, sizeof(msg), sigA, sizeof(sigA), &lenA),
                      LMS_OK, "sb15 sign A");
        expect_status(lms_sign(&privB, msg, sizeof(msg), sigB, sizeof(sigB), &lenB),
                      LMS_OK, "sb15 sign B");
        if (lenA == lenB && memcmp(sigB, sigA, lenA) != 0) {
            printf("FAIL: %s signature not byte-identical\n", label);
            g_failures++;
        }
        expect_status(lms_verify(&pub, msg, sizeof(msg), sigB, lenB), LMS_OK,
                      "sb15 verify");
    }

    lms_auth_path_backend_set(NULL, NULL);
    lms_tree_ctx_free(&ctx);
    expect_u64(ca.live_bytes, 0u, "sb15 no leak");
}

int main(void)
{
    test_estimate_memory();
    test_configure_within_budget();
    test_configure_overbudget();
    test_updates_formulas();
    test_invalid_input();
    test_ctx_lifecycle();
    test_ctx_alloc_failure_rollback();
    test_ctx_invalid_args();
    test_build_active_h5();
    test_build_active_multisublevel_unsupported();
    test_add_next_node_h15_subtree();
    test_keygen_root_h15();
    test_sign_init_auth_path_h15();
    test_sign_advance_rotation_h15();
    test_sign_backend_h5();
    test_sign_backend_h15();

    if (g_failures == 0) {
        printf("PASS: test_lms_subtree\n");
        return 0;
    }
    printf("FAIL: test_lms_subtree failures=%d\n", g_failures);
    return 1;
}
