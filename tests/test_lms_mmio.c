#include "../src/lms_internal.h"
#include "../src/lms_mmio.h"

#include <stdio.h>
#include <string.h>

#define FAKE_REG_BYTES 0x220u
#define FAKE_REG_WORDS (FAKE_REG_BYTES / 4u)

typedef enum {
    FAKE_SUCCESS = 0,
    FAKE_HARDWARE_ERROR,
    FAKE_TIMEOUT
} fake_mode_t;

typedef struct {
    uint32_t regs[FAKE_REG_WORDS];
    fake_mode_t mode;
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
        return 0u;
    }
    return fake->regs[offset / 4u];
}

static void fake_read_bytes(fake_mmio_t *fake,
                            uint32_t base,
                            uint8_t *bytes,
                            size_t length)
{
    size_t offset;
    for (offset = 0; offset < length; offset++) {
        uint32_t word = fake->regs[(base + (uint32_t)(offset & ~(size_t)3u)) / 4u];
        bytes[offset] = (uint8_t)(word >> (8u * (offset & 3u)));
    }
}

static void fake_write_bytes(fake_mmio_t *fake,
                             uint32_t base,
                             const uint8_t *bytes,
                             size_t length)
{
    size_t offset;
    for (offset = 0; offset < length; offset += 4u) {
        uint32_t word = 0u;
        size_t lane;
        for (lane = 0; lane < 4u && offset + lane < length; lane++) {
            word |= (uint32_t)bytes[offset + lane] << (8u * lane);
        }
        fake->regs[(base + (uint32_t)offset) / 4u] = word;
    }
}

static void fake_execute(fake_mmio_t *fake)
{
    uint32_t command = fake->regs[LMS_MMIO_REG_COMMAND / 4u];
    uint8_t input[LMS_MMIO_MAX_INPUT];
    uint8_t output[LMS_N];

    fake->start_count++;
    if (fake->mode == FAKE_TIMEOUT) {
        fake->regs[LMS_MMIO_REG_STATUS / 4u] = LMS_MMIO_STATUS_BUSY;
        return;
    }
    if (fake->mode == FAKE_HARDWARE_ERROR) {
        fake->regs[LMS_MMIO_REG_STATUS / 4u] = LMS_MMIO_STATUS_ERROR;
        fake->regs[LMS_MMIO_REG_ERROR / 4u] = LMS_MMIO_HW_ERR_CHAIN_RANGE;
        return;
    }

    if (command == LMS_MMIO_CMD_HASH_ONCE) {
        uint32_t length = fake->regs[LMS_MMIO_REG_INPUT_LENGTH / 4u];
        fake_read_bytes(fake, LMS_MMIO_REG_INPUT, input, length);
        if (lms_hash(LMS_HASH_SHA256, input, length, output, sizeof(output)) != 0) {
            fake->regs[LMS_MMIO_REG_STATUS / 4u] = LMS_MMIO_STATUS_ERROR;
            fake->regs[LMS_MMIO_REG_ERROR / 4u] = LMS_MMIO_HW_ERR_INTERNAL;
            return;
        }
    } else if (command == LMS_MMIO_CMD_CHAIN) {
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

static void setup_fake(fake_mmio_t *fake, fake_mode_t mode)
{
    memset(fake, 0, sizeof(*fake));
    fake->mode = mode;
    fake->regs[LMS_MMIO_REG_VERSION / 4u] = LMS_MMIO_VERSION_0_1;
    fake->regs[LMS_MMIO_REG_CAPABILITY / 4u] = LMS_MMIO_CAP_V0_REQUIRED;
}

static int init_client(lms_mmio_client_t *client,
                       fake_mmio_t *fake,
                       uint32_t timeout_polls,
                       int allow_fallback)
{
    lms_mmio_bus_t bus;
    bus.context = fake;
    bus.read32 = fake_read32;
    bus.write32 = fake_write32;
    return lms_mmio_client_init(client, &bus, timeout_polls, allow_fallback);
}

static int test_probe(void)
{
    fake_mmio_t fake;
    lms_mmio_client_t client;
    int failures = 0;

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&client, &fake, 4u, 0), LMS_MMIO_OK, "client init");
    failures += expect_status(lms_mmio_probe(&client), LMS_MMIO_OK, "probe v0.1");

    fake.regs[LMS_MMIO_REG_VERSION / 4u] = 0x00010000u;
    failures += expect_status(lms_mmio_probe(&client), LMS_MMIO_ERR_PROTOCOL, "reject version");
    fake.regs[LMS_MMIO_REG_VERSION / 4u] = LMS_MMIO_VERSION_0_1;
    fake.regs[LMS_MMIO_REG_CAPABILITY / 4u] = LMS_MMIO_CAP_SHA256 | LMS_MMIO_CAP_HASH_ONCE;
    failures += expect_status(lms_mmio_probe(&client), LMS_MMIO_OK, "probe hash-only capability");
    fake.regs[LMS_MMIO_REG_CAPABILITY / 4u] = LMS_MMIO_CAP_HASH_ONCE;
    failures += expect_status(lms_mmio_probe(&client), LMS_MMIO_ERR_PROTOCOL, "reject missing SHA256");
    return failures;
}

static int test_hash_once(void)
{
    static const uint8_t message[] = "abc";
    static const uint8_t expected[LMS_N] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    fake_mmio_t fake;
    lms_mmio_client_t client;
    uint8_t output[LMS_N];
    uint8_t packed[sizeof(message) - 1u];
    uint32_t cycles = 0u;
    int failures = 0;

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&client, &fake, 4u, 0), LMS_MMIO_OK, "hash client init");
    failures += expect_status(lms_mmio_hash_once(&client, message, sizeof(message) - 1u, output, &cycles),
                              LMS_MMIO_OK, "hash once");
    failures += expect_bytes(output, expected, sizeof(output), "hash output");
    fake_read_bytes(&fake, LMS_MMIO_REG_INPUT, packed, sizeof(packed));
    failures += expect_bytes(packed, message, sizeof(packed), "hash input packing");
    if (cycles != 1234u || fake.start_count != 1u || fake.clear_count != 1u ||
        fake.regs[LMS_MMIO_REG_INPUT / 4u] != 0x00636261u) {
        puts("FAIL: hash command metadata or little-endian packing");
        failures++;
    }
    failures += expect_status(lms_mmio_hash_once(&client, message, 129u, output, NULL),
                              LMS_MMIO_ERR_INVALID, "reject long hash");
    return failures;
}

static int test_chain(void)
{
    static const uint8_t expected[LMS_N] = {
        0x22, 0x65, 0x54, 0xe7, 0x47, 0xdf, 0xf2, 0x24,
        0x86, 0x98, 0xfb, 0x6a, 0x44, 0xde, 0xc1, 0x22,
        0xab, 0xea, 0x95, 0x36, 0x15, 0x00, 0xa1, 0x06,
        0x35, 0x93, 0x2d, 0xb0, 0x9a, 0xe7, 0xaf, 0xf7
    };
    fake_mmio_t fake;
    lms_mmio_client_t client;
    uint8_t I[LMS_I_LEN];
    uint8_t value[LMS_N];
    uint8_t original[LMS_N];
    uint32_t cycles = 0u;
    size_t index;
    int failures = 0;

    for (index = 0; index < sizeof(I); index++) {
        I[index] = (uint8_t)index;
    }
    for (index = 0; index < sizeof(value); index++) {
        value[index] = (uint8_t)index;
    }
    memcpy(original, value, sizeof(original));

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&client, &fake, 4u, 0), LMS_MMIO_OK, "chain client init");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 4u, 5u, value, &cycles),
                              LMS_MMIO_OK, "chain command");
    failures += expect_bytes(value, expected, sizeof(value), "chain output");
    if (cycles != 1234u || fake.regs[LMS_MMIO_REG_IDENTIFIER / 4u] != 0x03020100u ||
        fake.regs[LMS_MMIO_REG_ARG_Q / 4u] != 2u ||
        fake.regs[LMS_MMIO_REG_ARG_I / 4u] != 3u ||
        fake.regs[LMS_MMIO_REG_ARG_START / 4u] != 4u ||
        fake.regs[LMS_MMIO_REG_ARG_STEPS / 4u] != 5u) {
        puts("FAIL: chain command register packing");
        failures++;
    }

    memcpy(value, original, sizeof(value));
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 255u, 0u, value, NULL),
                              LMS_MMIO_OK, "zero-step chain");
    failures += expect_bytes(value, original, sizeof(value), "zero-step output");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 250u, 6u, value, NULL),
                              LMS_MMIO_ERR_INVALID, "reject chain overflow");
    memcpy(value, original, sizeof(value));
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 250u, 5u, value, NULL),
                              LMS_MMIO_OK, "maximum chain range");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 0x10000u, 0u, 1u, value, NULL),
                              LMS_MMIO_ERR_INVALID, "reject chain i");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 0x100u, 0u, value, NULL),
                              LMS_MMIO_ERR_INVALID, "reject chain start");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 0u, 0x100u, value, NULL),
                              LMS_MMIO_ERR_INVALID, "reject chain steps");
    return failures;
}

static int test_errors_and_fallback(void)
{
    static const uint8_t message[] = "abc";
    fake_mmio_t fake;
    lms_mmio_client_t client;
    uint8_t I[LMS_I_LEN];
    uint8_t output[LMS_N];
    uint8_t before[LMS_N];
    uint8_t chain_expected[LMS_N];
    uint32_t cycles = 99u;
    size_t index;
    int failures = 0;

    for (index = 0; index < sizeof(I); index++) {
        I[index] = (uint8_t)index;
    }
    for (index = 0; index < sizeof(output); index++) {
        output[index] = (uint8_t)index;
    }
    setup_fake(&fake, FAKE_SUCCESS);
    fake.regs[LMS_MMIO_REG_CAPABILITY / 4u] = LMS_MMIO_CAP_SHA256 | LMS_MMIO_CAP_HASH_ONCE;
    failures += expect_status(init_client(&client, &fake, 4u, 0), LMS_MMIO_OK, "hash-only client init");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 4u, 5u, output, NULL),
                              LMS_MMIO_ERR_PROTOCOL, "strict missing chain capability");
    if (fake.start_count != 0u || fake.clear_count != 0u) {
        puts("FAIL: missing capability touched command registers");
        failures++;
    }

    memset(output, 0x5a, sizeof(output));
    memcpy(before, output, sizeof(before));
    setup_fake(&fake, FAKE_HARDWARE_ERROR);
    failures += expect_status(init_client(&client, &fake, 4u, 0), LMS_MMIO_OK, "strict client init");
    failures += expect_status(lms_mmio_hash_once(&client, message, sizeof(message) - 1u, output, &cycles),
                              LMS_MMIO_ERR_HARDWARE, "strict hardware error");
    failures += expect_bytes(output, before, sizeof(output), "strict error output unchanged");
    if (client.last_hw_error != LMS_MMIO_HW_ERR_CHAIN_RANGE ||
        client.fallback_count != 0u || cycles != 0u) {
        puts("FAIL: strict hardware error observability");
        failures++;
    }

    setup_fake(&fake, FAKE_TIMEOUT);
    failures += expect_status(init_client(&client, &fake, 3u, 0), LMS_MMIO_OK, "timeout client init");
    failures += expect_status(lms_mmio_hash_once(&client, message, sizeof(message) - 1u, output, NULL),
                              LMS_MMIO_ERR_TIMEOUT, "strict timeout");
    if (client.fallback_count != 0u) {
        puts("FAIL: strict timeout used fallback");
        failures++;
    }

    setup_fake(&fake, FAKE_HARDWARE_ERROR);
    failures += expect_status(init_client(&client, &fake, 4u, 1), LMS_MMIO_OK, "fallback client init");
    failures += expect_status(lms_mmio_hash_once(&client, message, sizeof(message) - 1u, output, NULL),
                              LMS_MMIO_OK, "explicit hash fallback");
    if (client.fallback_count != 1u || client.last_hw_error != LMS_MMIO_HW_ERR_CHAIN_RANGE) {
        puts("FAIL: fallback counter or hardware error");
        failures++;
    }

    for (index = 0; index < sizeof(output); index++) {
        output[index] = (uint8_t)index;
    }
    memcpy(chain_expected, output, sizeof(chain_expected));
    failures += expect_status(lmots_chain_compute(I, LMS_HASH_SHA256, 2u, 3u, 4u, 5u, chain_expected),
                              LMS_OK, "chain fallback oracle");
    setup_fake(&fake, FAKE_TIMEOUT);
    failures += expect_status(init_client(&client, &fake, 2u, 1), LMS_MMIO_OK, "chain fallback client init");
    failures += expect_status(lms_mmio_chain(&client, I, 2u, 3u, 4u, 5u, output, NULL),
                              LMS_MMIO_OK, "explicit chain fallback");
    failures += expect_bytes(output, chain_expected, sizeof(output), "chain fallback output");
    if (client.fallback_count != 1u) {
        puts("FAIL: chain fallback counter");
        failures++;
    }
    return failures;
}

static int test_lmots_verify_backend(void)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t message[] = "MMIO verify backend";
    fake_mmio_t fake;
    lms_mmio_client_t client;
    lms_mmio_client_t fallback_client;
    lms_private_key_t priv;
    lms_public_key_t pub;
    uint8_t signature[LMS_MAX_SIGNATURE_LEN];
    size_t signature_len = 0u;
    int failures = 0;

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&client, &fake, 8u, 0), LMS_MMIO_OK,
                              "verify backend client init");
    failures += expect_status(lms_mmio_lmots_verify_enable(&client), LMS_MMIO_OK,
                              "enable strict verify backend");
    failures += expect_status(lms_private_key_init(&priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "verify backend private init");
    failures += expect_status(lms_public_key_generate(&priv, &pub), LMS_OK,
                              "verify backend public key");
    failures += expect_status(lms_sign(&priv, message, sizeof(message) - 1u,
                                       signature, sizeof(signature), &signature_len),
                              LMS_OK, "verify backend sign");
    if (fake.start_count != 0u || client.hardware_chain_count != 0u) {
        puts("FAIL: verify backend intercepted keygen or sign");
        failures++;
    }

    failures += expect_status(lms_verify(&pub, message, sizeof(message) - 1u,
                                         signature, signature_len),
                              LMS_OK, "hardware-backed verify");
    if (fake.start_count != 67u || client.hardware_chain_count != 67u ||
        client.hardware_chain_cycles != 67u * 1234u || client.fallback_count != 0u) {
        printf("FAIL: verify backend stats starts=%u hits=%llu cycles=%llu fallback=%u\n",
               (unsigned)fake.start_count,
               (unsigned long long)client.hardware_chain_count,
               (unsigned long long)client.hardware_chain_cycles,
               (unsigned)client.fallback_count);
        failures++;
    }

    fake.mode = FAKE_HARDWARE_ERROR;
    failures += expect_status(lms_verify(&pub, message, sizeof(message) - 1u,
                                         signature, signature_len),
                              LMS_ERR_VERIFY, "strict verify hardware failure");
    if (fake.start_count != 68u || client.hardware_chain_count != 67u ||
        client.fallback_count != 0u || client.last_hw_error != LMS_MMIO_HW_ERR_CHAIN_RANGE) {
        puts("FAIL: strict verify failure used fallback or lost hardware error");
        failures++;
    }
    lms_mmio_lmots_verify_disable();

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&fallback_client, &fake, 8u, 1), LMS_MMIO_OK,
                              "fallback verify client init");
    failures += expect_status(lms_mmio_lmots_verify_enable(&fallback_client),
                              LMS_MMIO_ERR_INVALID, "reject fallback verify backend");
    return failures;
}

static int test_lmots_sign_backend(void)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t message[] = "MMIO sign backend";
    fake_mmio_t fake;
    lms_mmio_client_t client;
    lms_mmio_client_t fallback_client;
    lms_private_key_t software_priv;
    lms_private_key_t hardware_priv;
    lms_private_key_t failure_priv;
    lms_public_key_t public_key;
    uint8_t software_signature[LMS_MAX_SIGNATURE_LEN];
    uint8_t hardware_signature[LMS_MAX_SIGNATURE_LEN];
    size_t software_length = 0u;
    size_t hardware_length = 0u;
    size_t failure_length = 0x55aau;
    int failures = 0;

    failures += expect_status(lms_private_key_init(&software_priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "software sign private init");
    failures += expect_status(lms_sign(&software_priv, message, sizeof(message) - 1u,
                                       software_signature, sizeof(software_signature),
                                       &software_length),
                              LMS_OK, "software reference sign");

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&client, &fake, 8u, 0), LMS_MMIO_OK,
                              "sign backend client init");
    failures += expect_status(lms_mmio_lmots_sign_enable_insecure(&client), LMS_MMIO_OK,
                              "enable strict sign backend");
    failures += expect_status(lms_private_key_init(&hardware_priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "hardware sign private init");
    failures += expect_status(lms_public_key_generate(&hardware_priv, &public_key), LMS_OK,
                              "sign backend public key");
    if (fake.start_count != 0u || client.hardware_chain_count != 0u) {
        puts("FAIL: sign backend intercepted key generation");
        failures++;
    }
    failures += expect_status(lms_sign(&hardware_priv, message, sizeof(message) - 1u,
                                       hardware_signature, sizeof(hardware_signature),
                                       &hardware_length),
                              LMS_OK, "hardware-backed sign");
    if (hardware_length != software_length ||
        memcmp(hardware_signature, software_signature, software_length) != 0) {
        puts("FAIL: hardware-backed signature differs from software reference");
        failures++;
    }
    if (hardware_priv.q != 1u || fake.start_count != 67u ||
        fake.chain_steps != 495u ||
        client.hardware_chain_count != 67u ||
        client.hardware_chain_cycles != 67u * 1234u || client.fallback_count != 0u) {
        printf("FAIL: sign backend q=%u starts=%u hits=%llu cycles=%llu fallback=%u\n",
               (unsigned)hardware_priv.q, (unsigned)fake.start_count,
               (unsigned long long)client.hardware_chain_count,
               (unsigned long long)client.hardware_chain_cycles,
               (unsigned)client.fallback_count);
        failures++;
    }
    printf("LM-OTS Sign hardware baseline: calls=%u steps=%llu fake_cycles=%llu\n",
           (unsigned)fake.start_count,
           (unsigned long long)fake.chain_steps,
           (unsigned long long)client.hardware_chain_cycles);
    failures += expect_status(lms_verify(&public_key, message, sizeof(message) - 1u,
                                         hardware_signature, hardware_length),
                              LMS_OK, "verify hardware-backed signature");
    if (fake.start_count != 67u || client.hardware_chain_count != 67u) {
        puts("FAIL: sign backend intercepted Verify");
        failures++;
    }
    lms_mmio_lmots_sign_disable();

    setup_fake(&fake, FAKE_HARDWARE_ERROR);
    failures += expect_status(init_client(&client, &fake, 8u, 0), LMS_MMIO_OK,
                              "failing sign client init");
    failures += expect_status(lms_mmio_lmots_sign_enable_insecure(&client), LMS_MMIO_OK,
                              "enable failing sign backend");
    failures += expect_status(lms_private_key_init(&failure_priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "failing sign private init");
    failures += expect_status(lms_sign(&failure_priv, message, sizeof(message) - 1u,
                                       hardware_signature, sizeof(hardware_signature),
                                       &failure_length),
                              LMS_ERR_INVALID, "strict sign hardware failure");
    if (failure_priv.q != 0u || failure_length != 0x55aau || fake.start_count != 1u ||
        client.hardware_chain_count != 0u || client.fallback_count != 0u ||
        client.last_hw_error != LMS_MMIO_HW_ERR_CHAIN_RANGE) {
        puts("FAIL: strict sign failure committed q, changed length, or used fallback");
        failures++;
    }
    lms_mmio_lmots_sign_disable();

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&fallback_client, &fake, 8u, 1), LMS_MMIO_OK,
                              "fallback sign client init");
    failures += expect_status(lms_mmio_lmots_sign_enable_insecure(&fallback_client),
                              LMS_MMIO_ERR_INVALID, "reject fallback sign backend");
    return failures;
}

static int test_lmots_keygen_backend(void)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    fake_mmio_t fake;
    lms_mmio_client_t client;
    lms_mmio_client_t fallback_client;
    lms_private_key_t software_priv;
    lms_private_key_t hardware_priv;
    lms_public_key_t software_public;
    lms_public_key_t hardware_public;
    uint8_t software_bytes[LMS_PUBLIC_KEY_LEN];
    uint8_t hardware_bytes[LMS_PUBLIC_KEY_LEN];
    int failures = 0;

    failures += expect_status(lms_private_key_init(&software_priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "software keygen private init");
    failures += expect_status(lms_public_key_generate(&software_priv, &software_public),
                              LMS_OK, "software public key generation");
    failures += expect_status(lms_public_key_serialize(&software_public, software_bytes,
                                                       sizeof(software_bytes)),
                              LMS_OK, "serialize software public key");

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&client, &fake, 8u, 0), LMS_MMIO_OK,
                              "keygen backend client init");
    failures += expect_status(lms_mmio_lmots_keygen_enable_insecure(&client), LMS_MMIO_OK,
                              "enable strict keygen backend");
    failures += expect_status(lms_private_key_init(&hardware_priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "hardware keygen private init");
    failures += expect_status(lms_public_key_generate(&hardware_priv, &hardware_public),
                              LMS_OK, "hardware-backed public key generation");
    failures += expect_status(lms_public_key_serialize(&hardware_public, hardware_bytes,
                                                       sizeof(hardware_bytes)),
                              LMS_OK, "serialize hardware public key");
    failures += expect_bytes(hardware_bytes, software_bytes, sizeof(hardware_bytes),
                             "hardware-backed public key");
    if (fake.start_count != 2144u || fake.chain_steps != 32160u ||
        client.hardware_chain_count != 2144u ||
        client.hardware_chain_cycles != 2144u * 1234u || client.fallback_count != 0u) {
        printf("FAIL: keygen backend starts=%u steps=%llu hits=%llu cycles=%llu fallback=%u\n",
               (unsigned)fake.start_count,
               (unsigned long long)fake.chain_steps,
               (unsigned long long)client.hardware_chain_count,
               (unsigned long long)client.hardware_chain_cycles,
               (unsigned)client.fallback_count);
        failures++;
    }
    printf("LM-OTS KeyGen hardware baseline: calls=%u steps=%llu fake_cycles=%llu\n",
           (unsigned)fake.start_count,
           (unsigned long long)fake.chain_steps,
           (unsigned long long)client.hardware_chain_cycles);
    lms_mmio_lmots_keygen_disable();

    setup_fake(&fake, FAKE_HARDWARE_ERROR);
    failures += expect_status(init_client(&client, &fake, 8u, 0), LMS_MMIO_OK,
                              "failing keygen client init");
    failures += expect_status(lms_mmio_lmots_keygen_enable_insecure(&client), LMS_MMIO_OK,
                              "enable failing keygen backend");
    failures += expect_status(lms_public_key_generate(&hardware_priv, &hardware_public),
                              LMS_ERR_INVALID, "strict keygen hardware failure");
    if (fake.start_count != 1u || client.hardware_chain_count != 0u ||
        client.fallback_count != 0u ||
        client.last_hw_error != LMS_MMIO_HW_ERR_CHAIN_RANGE) {
        puts("FAIL: strict keygen failure continued, used fallback, or lost hardware error");
        failures++;
    }
    lms_mmio_lmots_keygen_disable();

    setup_fake(&fake, FAKE_SUCCESS);
    failures += expect_status(init_client(&fallback_client, &fake, 8u, 1), LMS_MMIO_OK,
                              "fallback keygen client init");
    failures += expect_status(lms_mmio_lmots_keygen_enable_insecure(&fallback_client),
                              LMS_MMIO_ERR_INVALID, "reject fallback keygen backend");
    return failures;
}

/* Randomizer C source routing (TRNG-C scheme, finalized 2026-08-22):
 * via lmots_sign_prepare, goes directly through the registered randomizer backend
 * (lmots_mmio_sign_randomizer -> lmots_mmio_get_randomizer_c), exercising two new branches:
 *   1. debug C_LOAD slot: client->randomizer_c_slot non-null -> memcpy slot contents as C;
 *   2. deployed TRNG: client->trng_fill_c non-null -> callback fills C (mock uses a fixed pattern).
 * (The unset-source fallback branch is implicitly covered by the existing
 * test_lmots_sign_backend software C path.) */
static int mock_trng_fill_c(void *context, uint8_t out[LMS_N])
{
    memcpy(out, (const uint8_t *)context, LMS_N);
    return 0;
}

static int test_randomizer_c_source(void)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t cslot[LMS_N] = {
        0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1,
        0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
        0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1,
        0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9
    };
    static const uint8_t trng_pattern[LMS_N] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    uint8_t message[4] = { 't', 'e', 's', 't' };
    fake_mmio_t fake;
    lms_mmio_client_t client;
    lms_private_key_t priv;
    uint8_t C[LMS_N];
    uint8_t coefficients[LMS_MAX_OTS_P];
    int failures = 0;

    setup_fake(&fake, FAKE_SUCCESS);
    /* Needs the DERIVE_CHAIN capability: lms_mmio_lmots_sign_enable_insecure registers the
     * randomizer backend based on it (otherwise sign falls back to software C and this
     * route cannot be tested). */
    fake.regs[LMS_MMIO_REG_CAPABILITY / 4u] = LMS_MMIO_CAP_SHA256 | LMS_MMIO_CAP_HASH_ONCE |
                                              LMS_MMIO_CAP_CHAIN | LMS_MMIO_CAP_DERIVE_CHAIN;
    failures += expect_status(init_client(&client, &fake, 8u, 0), LMS_MMIO_OK,
                              "csource client init");
    failures += expect_status(lms_mmio_probe(&client), LMS_MMIO_OK, "csource probe");
    failures += expect_status(lms_private_key_init(&priv, LMS_SHA256_N32_H5,
                                                   LMOTS_SHA256_N32_W4, I, seed),
                              LMS_OK, "csource private init");
    failures += expect_status(lms_mmio_lmots_sign_enable_insecure(&client), LMS_MMIO_OK,
                              "csource enable randomizer backend");

    /* 1. debug C_LOAD slot: C must equal the slot contents */
    client.randomizer_c_slot = cslot;
    failures += expect_status(lmots_sign_prepare(&priv, 0u, message, sizeof(message),
                                                 C, coefficients),
                              LMS_OK, "csource slot prepare");
    failures += expect_bytes(C, cslot, LMS_N, "csource slot C==cslot");

    /* 2. deployed TRNG: C must equal the mock-filled pattern */
    client.randomizer_c_slot = NULL;
    client.trng_fill_c = mock_trng_fill_c;
    client.trng_context = (void *)trng_pattern;
    failures += expect_status(lmots_sign_prepare(&priv, 0u, message, sizeof(message),
                                                 C, coefficients),
                              LMS_OK, "csource trng prepare");
    failures += expect_bytes(C, trng_pattern, LMS_N, "csource trng C==pattern");

    /* Cleanup, to avoid affecting subsequent tests */
    client.trng_fill_c = NULL;
    client.randomizer_c_slot = NULL;
    lms_mmio_lmots_sign_disable();
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += test_probe();
    failures += test_hash_once();
    failures += test_chain();
    failures += test_errors_and_fallback();
    failures += test_lmots_verify_backend();
    failures += test_lmots_sign_backend();
    failures += test_lmots_keygen_backend();
    failures += test_randomizer_c_source();

    if (failures) {
        printf("LMS MMIO tests failed: %d\n", failures);
        return 1;
    }

    puts("LMS MMIO tests passed");
    return 0;
}