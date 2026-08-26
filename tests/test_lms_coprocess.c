/* LMS layer (Merkle tree) software/hardware co-design pipeline test.
 *
 * Validates the lms_coprocess module:
 *   1. Tree build (software K_q source): root/auth path exactly match the existing
 *      pure-software lms_public_key_generate / lms_tree_node (semantic correctness).
 *   2. Hardware co-design: after registering the chain backend via fake-MMIO
 *      (lms_mmio_lmots_keygen_enable), the default K_q source automatically uses the
 *      hardware chain; the built tree is byte-identical to pure software (SW/HW parity + fallback=0).
 *   3. Verify co-design: software D_LEAF/D_INTR tree verification of the K_v produced by
 *      the hardware backend; correct path passes, tampered path rejected.
 *
 * Hardware never touches the tree layers: fake-MMIO only provides LM-OTS chains/public
 * keys; all D_LEAF/D_INTR work stays on the software side of this module.
 */

#include "../src/lms_internal.h"
#include "../src/lms_coprocess.h"
#include "../src/lms_mmio.h"

#include <stdio.h>
#include <string.h>

#define FAKE_REG_BYTES 0x220u
#define FAKE_REG_WORDS (FAKE_REG_BYTES / 4u)

typedef struct {
    uint32_t regs[FAKE_REG_WORDS];
    uint32_t start_count;
    uint32_t clear_count;
    uint64_t chain_steps;
} fake_mmio_t;

static int expect_status(int actual, int expected, const char *label)
{
    if (actual != expected) {
        printf("FAIL: %s expected %d, got %d\n", label, expected, actual);
        return 1;
    }
    return 0;
}

static int expect_bytes(const uint8_t *actual,
                        const uint8_t *expected,
                        size_t length,
                        const char *label)
{
    if (memcmp(actual, expected, length) != 0) {
        printf("FAIL: %s mismatch\n", label);
        return 1;
    }
    return 0;
}

static uint32_t fake_read32(void *context, uint32_t offset)
{
    fake_mmio_t *fake = (fake_mmio_t *)context;
    if ((offset & 3u) != 0u || offset >= FAKE_REG_BYTES) {
        return 0;
    }
    return fake->regs[offset / 4u];
}

static void fake_read_bytes(fake_mmio_t *fake,
                            uint32_t base,
                            uint8_t *out,
                            size_t length)
{
    size_t offset;
    for (offset = 0; offset < length; offset++) {
        uint32_t word = fake->regs[(base + (uint32_t)(offset & ~(size_t)3u)) / 4u];
        out[offset] = (uint8_t)(word >> ((offset & 3u) * 8u));
    }
}

static void fake_write_bytes(fake_mmio_t *fake,
                             uint32_t base,
                             const uint8_t *in,
                             size_t length)
{
    size_t offset;
    for (offset = 0; offset < length; offset++) {
        uint32_t word = fake->regs[(base + (uint32_t)(offset & ~(size_t)3u)) / 4u];
        uint32_t shift = (uint32_t)(offset & 3u) * 8u;
        word &= ~(0xffu << shift);
        word |= ((uint32_t)in[offset]) << shift;
        fake->regs[(base + (uint32_t)(offset & ~(size_t)3u)) / 4u] = word;
    }
}

static void fake_execute(fake_mmio_t *fake)
{
    uint32_t command = fake->regs[LMS_MMIO_REG_COMMAND / 4u];
    uint8_t output[LMS_N];

    fake->start_count++;

    if (command == LMS_MMIO_CMD_CHAIN) {
        uint8_t I[LMS_I_LEN];
        fake->chain_steps += fake->regs[LMS_MMIO_REG_ARG_STEPS / 4u];
        fake_read_bytes(fake, LMS_MMIO_REG_IDENTIFIER, I, sizeof(I));
        fake_read_bytes(fake, LMS_MMIO_REG_INPUT, output, sizeof(output));
        if (lmots_chain_compute(I,
                                LMS_HASH_SHA256,
                                fake->regs[LMS_MMIO_REG_ARG_Q / 4u],
                                fake->regs[LMS_MMIO_REG_ARG_I / 4u],
                                fake->regs[LMS_MMIO_REG_ARG_START / 4u],
                                fake->regs[LMS_MMIO_REG_ARG_STEPS / 4u],
                                output) != LMS_OK) {
            fake->regs[LMS_MMIO_REG_STATUS / 4u] = LMS_MMIO_STATUS_ERROR;
            fake->regs[LMS_MMIO_REG_ERROR / 4u] = LMS_MMIO_HW_ERR_CHAIN_RANGE;
            return;
        }
    } else {
        fake->regs[LMS_MMIO_REG_STATUS / 4u] = LMS_MMIO_STATUS_ERROR;
        fake->regs[LMS_MMIO_REG_ERROR / 4u] = LMS_MMIO_HW_ERR_UNSUPPORTED_COMMAND;
        return;
    }

    fake_write_bytes(fake, LMS_MMIO_REG_OUTPUT, output, sizeof(output));
    fake->regs[LMS_MMIO_REG_CYCLE_COUNT / 4u] = 1234u;
    fake->regs[LMS_MMIO_REG_STATUS / 4u] = LMS_MMIO_STATUS_DONE;
}

static void fake_write32(void *context, uint32_t offset, uint32_t value)
{
    fake_mmio_t *fake = (fake_mmio_t *)context;
    if ((offset & 3u) != 0u || offset >= FAKE_REG_BYTES) {
        return;
    }
    if (offset == LMS_MMIO_REG_CONTROL && value == LMS_MMIO_CTRL_CLEAR) {
        fake->clear_count++;
        fake->regs[LMS_MMIO_REG_STATUS / 4u] = 0u;
        fake->regs[LMS_MMIO_REG_ERROR / 4u] = 0u;
        fake->regs[LMS_MMIO_REG_CYCLE_COUNT / 4u] = 0u;
        return;
    }
    fake->regs[offset / 4u] = value;
    if (offset == LMS_MMIO_REG_CONTROL && value == LMS_MMIO_CTRL_START) {
        fake_execute(fake);
    }
}

static void setup_fake(fake_mmio_t *fake)
{
    memset(fake, 0, sizeof(*fake));
    fake->regs[LMS_MMIO_REG_VERSION / 4u] = LMS_MMIO_VERSION_0_1;
    fake->regs[LMS_MMIO_REG_CAPABILITY / 4u] = LMS_MMIO_CAP_V0_REQUIRED;
}

static int init_client(lms_mmio_client_t *client, fake_mmio_t *fake)
{
    lms_mmio_bus_t bus;
    bus.context = fake;
    bus.read32 = fake_read32;
    bus.write32 = fake_write32;
    return lms_mmio_client_init(client, &bus, 8u, 0);
}

static void make_key(lms_private_key_t *priv, uint8_t seed_tag)
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

/* 1. Tree built with the software K_q source == existing lms_public_key_generate / lms_tree_node. */
static int test_build_matches_reference(void)
{
    lms_private_key_t priv;
    lms_public_key_t pub;
    lms_coprocess_tree_t tree;
    uint8_t root[LMS_N];
    uint8_t node_ref[LMS_N];
    uint8_t node_cop[LMS_N];
    uint8_t path[LMS_MAX_HEIGHT * LMS_N];
    uint32_t height;
    uint32_t i;
    int failures = 0;

    make_key(&priv, 0x00u);
    failures += expect_status(lms_public_key_generate(&priv, &pub), LMS_OK,
                              "reference public key generation");

    failures += expect_status(lms_coprocess_tree_init(&tree, LMS_SHA256_N32_H5, priv.I),
                              LMS_OK, "coprocess tree init");
    failures += expect_status(lms_coprocess_build(&tree, &priv, NULL, NULL), LMS_OK,
                              "coprocess build (software source)");
    failures += expect_status(lms_coprocess_root(&tree, root), LMS_OK, "coprocess root");
    failures += expect_bytes(root, pub.root, LMS_N, "coprocess root == reference root");

    /* Spot-check several nodes (leaf/internal/root) against lms_tree_node. */
    {
        static const uint32_t probes[] = {1u, 2u, 3u, 5u, 16u, 17u, 31u, 32u, 33u, 47u, 63u};
        for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            failures += expect_status(lms_tree_node(&priv, probes[i], node_ref), LMS_OK,
                                      "reference tree node");
            failures += expect_status(lms_coprocess_node(&tree, probes[i], node_cop), LMS_OK,
                                      "coprocess node");
            failures += expect_bytes(node_cop, node_ref, LMS_N, "node parity");
        }
    }

    /* Auth path matches the existing signature path (lms_sign.c sibling loop). */
    height = tree.height;
    failures += expect_status(lms_coprocess_auth_path(&tree, 7u, path), LMS_OK,
                              "coprocess auth path");
    {
        uint32_t node_num = (1u << height) + 7u;
        for (i = 0; i < height; i++) {
            uint32_t sibling = node_num ^ 1u;
            failures += expect_status(lms_tree_node(&priv, sibling, node_ref), LMS_OK,
                                      "reference sibling node");
            failures += expect_bytes(path + (size_t)i * LMS_N, node_ref, LMS_N,
                                     "auth path sibling parity");
            node_num /= 2u;
        }
    }
    return failures;
}

/* 2. Hardware co-design: after registering the chain backend, the default K_q source uses hardware; the tree matches pure software and fallback=0. */
static int test_hardware_backend_parity(void)
{
    lms_private_key_t priv;
    lms_coprocess_tree_t tree;
    lms_public_key_t pub;
    fake_mmio_t fake;
    lms_mmio_client_t client;
    uint8_t root[LMS_N];
    int failures = 0;

    make_key(&priv, 0x20u);
    failures += expect_status(lms_public_key_generate(&priv, &pub), LMS_OK,
                              "reference keygen for hw parity");

    setup_fake(&fake);
    failures += expect_status(init_client(&client, &fake), LMS_MMIO_OK, "hw client init");
    failures += expect_status(lms_mmio_lmots_keygen_enable_insecure(&client), LMS_MMIO_OK,
                              "enable hw keygen chain backend");

    /* Default source NULL -> lmots_public_from_private -> the registered hardware chain backend. */
    failures += expect_status(lms_coprocess_tree_init(&tree, LMS_SHA256_N32_H5, priv.I),
                              LMS_OK, "hw coprocess tree init");
    failures += expect_status(lms_coprocess_build(&tree, &priv, NULL, NULL), LMS_OK,
                              "hw-backed coprocess build");
    failures += expect_status(lms_coprocess_root(&tree, root), LMS_OK, "hw coprocess root");
    failures += expect_bytes(root, pub.root, LMS_N, "hw-backed root == reference root");

    /* H5/W4: 67 chains x 15 steps x 32 leaves = 32160 steps; 2144 hardware hits, zero fallback. */
    if (fake.start_count != 2144u || fake.chain_steps != 32160u ||
        client.hardware_chain_count != 2144u || client.fallback_count != 0u) {
        printf("FAIL: hw coprocess hits starts=%u steps=%llu hits=%llu fallback=%u\n",
               (unsigned)fake.start_count,
               (unsigned long long)fake.chain_steps,
               (unsigned long long)client.hardware_chain_count,
               (unsigned)client.fallback_count);
        failures++;
    }
    printf("LMS-tree coprocess hardware baseline: leaves=32 calls=%u steps=%llu fallback=%u\n",
           (unsigned)fake.start_count,
           (unsigned long long)fake.chain_steps,
           (unsigned)client.fallback_count);
    lms_mmio_lmots_keygen_disable();
    return failures;
}

/* 3. Verify co-design: the hardware backend produces K_v; software D_LEAF/D_INTR does tree verification. */
static int test_verify_coprocess(void)
{
    lms_private_key_t priv;
    lms_coprocess_tree_t tree;
    fake_mmio_t fake;
    lms_mmio_client_t client;
    uint8_t kv[LMS_N];
    uint8_t path[LMS_MAX_HEIGHT * LMS_N];
    uint32_t q = 7u;
    int failures = 0;

    make_key(&priv, 0x40u);
    failures += expect_status(lms_coprocess_tree_init(&tree, LMS_SHA256_N32_H5, priv.I),
                              LMS_OK, "verify tree init");
    failures += expect_status(lms_coprocess_build(&tree, &priv, NULL, NULL), LMS_OK,
                              "verify tree build");

    setup_fake(&fake);
    failures += expect_status(init_client(&client, &fake), LMS_MMIO_OK, "verify hw client");
    failures += expect_status(lms_mmio_lmots_keygen_enable_insecure(&client), LMS_MMIO_OK,
                              "enable hw backend for K_v source");

    /* Hardware backend produces the LM-OTS public-key candidate K_v (= K_q of leaf q). */
    failures += expect_status(lmots_public_from_private(&priv, q, kv), LMS_OK,
                              "hw-backed K_v for verify");
    lms_mmio_lmots_keygen_disable();

    failures += expect_status(lms_coprocess_auth_path(&tree, q, path), LMS_OK,
                              "auth path for verify");

    /* Correct path: software tree verification passes, rebuilt root == tree root. */
    failures += expect_status(lms_coprocess_verify(&tree, q, kv, path), LMS_OK,
                              "coprocess tree verify (correct path)");

    /* Tampered path (flip the first byte): must be rejected. */
    path[0] ^= 0x01u;
    failures += expect_status(lms_coprocess_verify(&tree, q, kv, path), LMS_ERR_VERIFY,
                              "coprocess tree verify rejects tampered path");
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += test_build_matches_reference();
    failures += test_hardware_backend_parity();
    failures += test_verify_coprocess();

    if (failures) {
        printf("LMS coprocess tests failed: %d\n", failures);
        return 1;
    }

    puts("LMS coprocess tests passed");
    return 0;
}
