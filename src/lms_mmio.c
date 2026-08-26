#include "lms_mmio.h"

#include "lms_internal.h"

#include <string.h>

/* ---- SoC cycle counting (LMS_MMIO_SOC_PROFILE debug builds only; not compiled on the PC side) ---- */
#if defined(LMS_MMIO_SOC_PROFILE)
#include <stdint.h>
#define LMS_SOC_CYCLE_COUNT_ADDR 0x10000010u
static uint32_t soc_cycle_count(void)
{
    return *(volatile uint32_t *)(uintptr_t)LMS_SOC_CYCLE_COUNT_ADDR;
}
#endif

/* ---- Hash descriptors (compile-time constants, one static instance per hash) ---- */
const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHA256 = {
    LMS_HASH_SHA256,                    /* hash_alg */
    0x00000007u,                        /* version */
    LMS_MMIO_CAP_SHA256,                /* probe_cap */
    128u,                               /* max_input_bytes */
    "SHA-256"
};

const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHAKE256 = {
    LMS_HASH_SHAKE256,                  /* hash_alg */
    0x00000001u,                        /* version */
    LMS_MMIO_CAP_SHAKE256,              /* probe_cap: bit12 */
    136u,                               /* max_input_bytes */
    "SHAKE256"
};

/* ---- Internal helpers ---- */

static uint32_t direct_read32(void *context, uint32_t offset)
{
    volatile uint32_t *reg = (volatile uint32_t *)((volatile uint8_t *)context + offset);
    return *reg;
}

static void direct_write32(void *context, uint32_t offset, uint32_t value)
{
    volatile uint32_t *reg = (volatile uint32_t *)((volatile uint8_t *)context + offset);
    *reg = value;
}

/* Validate lmots_type and derive the Winternitz parameters (stage 2: the hardware chain engine
 * is parameterized with w∈{1,2,4,8}). LM-OTS types outside w=1/2/4/8 (e.g. varying n) are not
 * supported by hardware -> invalid. */
static int lmots_param_hw(lmots_param_t *param, uint32_t lmots_type)
{
    if (lms_get_lmots_param(lmots_type, param) != LMS_OK) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (param->w != 1u && param->w != 2u && param->w != 4u && param->w != 8u) {
        return LMS_MMIO_ERR_INVALID;
    }
    return LMS_MMIO_OK;
}

/* Coefficient packing (aligned with the RTL coefficient_words[0:31] compact layout, unified on
 * both platforms): 32/w coefficients per word; coefficient i sits in word i/(32/w) at bit
 * (i%(32/w))*w. W1:32x1 / W2:16x2 / W4:8x4 / W8:4x8. (W1 p=265 -> 9 words ≤ 32)
 * Returns the number of packed words. words must have 32 entries. (REVIEW B05B06-R11: the
 * obsolete per_byte parameter has been removed -- since S5 both platforms pack compactly, no
 * per-byte layout.) */
static uint32_t pack_coefficients_words(uint32_t *words,
                                        const uint8_t *coefficients,
                                        uint32_t p,
                                        uint32_t w)
{
    uint32_t i;
    uint32_t per;
    uint32_t mask;
    uint32_t shift;
    uint32_t w_idx = 0u;
    uint32_t w_shift = 0u;

    per = 32u / w;            /* compact: 32/w per word */
    mask = (w == 8u) ? 0xffu : ((1u << w) - 1u);
    shift = w;
    for (i = 0u; i < 32u; i++) {
        words[i] = 0u;
    }
    /* Incremental bit offset instead of per-coefficient division/modulo (per*shift==32, so w_shift
     * wraps every per coefficients): RV32 div/mod is ~20-40 cycles vs ~1 for shift/mask -- the
     * signing hot path (the PROF write bulk). */
    for (i = 0u; i < p; i++) {
        words[w_idx] |= ((uint32_t)coefficients[i] & mask) << w_shift;
        w_shift += shift;
        if (w_shift >= 32u) {
            w_shift -= 32u;
            w_idx++;
        }
    }
    return (p + per - 1u) / per;
}

void lms_mmio_bus_init_direct(lms_mmio_bus_t *bus, volatile void *base)
{
    if (bus) {
        bus->context = (void *)base;
        bus->read32 = direct_read32;
        bus->write32 = direct_write32;
    }
}

int lms_mmio_client_init(lms_mmio_client_t *client,
                         const lms_mmio_bus_t *bus,
                         uint32_t timeout_polls,
                         int allow_fallback)
{
    if (!client || !bus || !bus->read32 || !bus->write32 || timeout_polls == 0u) {
        return LMS_MMIO_ERR_INVALID;
    }

    memset(client, 0, sizeof(*client));
    client->bus = *bus;
    client->timeout_polls = timeout_polls;
    client->allow_fallback = allow_fallback != 0;
    client->hash_desc = NULL;
    return LMS_MMIO_OK;
}

int lms_mmio_probe(lms_mmio_client_t *client)
{
    uint32_t version;
    uint32_t capabilities;

    if (!client || !client->bus.read32) {
        return LMS_MMIO_ERR_INVALID;
    }

    version      = client->bus.read32(client->bus.context, LMS_MMIO_REG_VERSION);
    capabilities = client->bus.read32(client->bus.context, LMS_MMIO_REG_CAPABILITY);
    client->probed      = 0;
    client->capabilities = capabilities;
    client->hash_desc   = NULL;

    /* Match by descriptor: SHAKE256 is detected first (uniquely identified by bit12, version 1),
     * then SHA-256 (bit0 + version range 1-7). */
    if ((capabilities & LMS_MMIO_HASH_DESC_SHAKE256.probe_cap) &&
        version == LMS_MMIO_HASH_DESC_SHAKE256.version) {
        client->hash_desc = &LMS_MMIO_HASH_DESC_SHAKE256;
    } else if ((capabilities & LMS_MMIO_HASH_DESC_SHA256.probe_cap) &&
               version >= 1u && version <= LMS_MMIO_HASH_DESC_SHA256.version) {
        client->hash_desc = &LMS_MMIO_HASH_DESC_SHA256;
    }

    if (!client->hash_desc) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    client->probed = 1;
    return LMS_MMIO_OK;
}

/* Register-window byte write. Contract (REVIEW B05B06-R8): length may be a non-multiple of 4 --
 * the slow path writes word by word per ceil(length/4), zero-filling the high bytes of the last
 * word; hardware trims per the length registers such as INPUT_LENGTH, ignoring the padding bytes.
 * read_bytes is analogous (the high bytes of the last word are dropped). */
static void write_bytes(const lms_mmio_bus_t *bus,
                        uint32_t base,
                        const uint8_t *bytes,
                        size_t length)
{
    size_t offset;

    /* F3: 4B-aligned fast path (length is a whole number of words and the pointer is 4B-aligned;
     * RV32 little-endian direct word moves, avoiding per-byte packing; same pattern as the
     * write_task_bytes stream-region fast path) */
    if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {
        const uint32_t *wp = (const uint32_t *)(const void *)bytes;
        for (offset = 0; offset < length; offset += 4u) {
            bus->write32(bus->context, base + (uint32_t)offset, wp[offset >> 2]);
        }
        return;
    }
    for (offset = 0; offset < length; offset += 4u) {
        uint32_t word = 0;
        size_t lane;
        for (lane = 0; lane < 4u && offset + lane < length; lane++) {
            word |= (uint32_t)bytes[offset + lane] << (8u * lane);
        }
        bus->write32(bus->context, base + (uint32_t)offset, word);
    }
}

static void read_bytes(const lms_mmio_bus_t *bus,
                       uint32_t base,
                       uint8_t *bytes,
                       size_t length)
{
    size_t offset;

    /* F3: 4B-aligned fast path (same as write_bytes) */
    if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {
        uint32_t *wp = (uint32_t *)(void *)bytes;
        for (offset = 0; offset < length; offset += 4u) {
            wp[offset >> 2] = bus->read32(bus->context, base + (uint32_t)offset);
        }
        return;
    }
    for (offset = 0; offset < length; offset += 4u) {
        uint32_t word = bus->read32(bus->context, base + (uint32_t)offset);
        size_t lane;
        for (lane = 0; lane < 4u && offset + lane < length; lane++) {
            bytes[offset + lane] = (uint8_t)(word >> (8u * lane));
        }
    }
}

static void write_task_bytes(const lms_mmio_bus_t *bus,
                             uint32_t word_base,
                             const uint8_t *bytes,
                             size_t length)
{
    size_t offset;
    if (word_base >= LMS_MMIO_TASK_STREAM_BASE) {
        /* Stream region (≥17, write side auto-increments since VERSION 8+): one ADDR + consecutive
         * DATA writes, eliminating the per-word address write (Verify's 2144B signature write drops
         * from 1072 transactions to 537). */
        bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR, word_base);
        if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {
            /* 4B-aligned fast path: RV32 little-endian, direct word reads avoid per-byte packing */
            const uint32_t *wp = (const uint32_t *)(const void *)bytes;
            size_t n = length >> 2;
            for (offset = 0; offset < n; offset++) {
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, wp[offset]);
            }
        } else {
            for (offset = 0; offset < length; offset += 4u) {
                uint32_t word = 0u;
                size_t lane;
                for (lane = 0; lane < 4u && offset + lane < length; lane++) {
                    word |= (uint32_t)bytes[offset + lane] << (8u * lane);
                }
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, word);
            }
        }
    } else {
        /* Coefficient region (<17): per-word ADDR+DATA (write side does not auto-increment) */
        if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {
            const uint32_t *wp = (const uint32_t *)(const void *)bytes;
            size_t n = length >> 2;
            for (offset = 0; offset < n; offset++) {
                bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR,
                             word_base + (uint32_t)offset);
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, wp[offset]);
            }
        } else {
            for (offset = 0; offset < length; offset += 4u) {
                uint32_t word = 0u;
                size_t lane;
                for (lane = 0; lane < 4u && offset + lane < length; lane++) {
                    word |= (uint32_t)bytes[offset + lane] << (8u * lane);
                }
                bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR,
                             word_base + (uint32_t)(offset / 4u));
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, word);
            }
        }
    }
}

static void read_task_bytes(const lms_mmio_bus_t *bus,
                            uint32_t word_base,
                            uint8_t *bytes,
                            size_t length)
{
    size_t offset;
    /* VERSION 7+: set the base address once; subsequent REG_TASK_DATA reads auto-increment the
     * address in hardware, eliminating one address-write MMIO transaction per word (536 -> 1,
     * saving ~535 writes). */
    bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR, word_base);
    if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {
        /* 4B-aligned fast path: RV32 little-endian, direct word stores avoid per-byte unpacking */
        uint32_t *wp = (uint32_t *)(void *)bytes;
        size_t n = length >> 2;
        for (offset = 0; offset < n; offset++) {
            wp[offset] = bus->read32(bus->context, LMS_MMIO_REG_TASK_DATA);
        }
    } else {
        for (offset = 0; offset < length; offset += 4u) {
            uint32_t word;
            size_t lane;
            word = bus->read32(bus->context, LMS_MMIO_REG_TASK_DATA);
            for (lane = 0; lane < 4u && offset + lane < length; lane++) {
                bytes[offset + lane] = (uint8_t)(word >> (8u * lane));
            }
        }
    }
}

static int ensure_probe(lms_mmio_client_t *client)
{
    return client->probed ? LMS_MMIO_OK : lms_mmio_probe(client);
}

static int wait_for_result_n(lms_mmio_client_t *client,
                             uint8_t *output,
                             size_t output_len,
                             uint32_t *cycles)
{
    uint32_t poll;

    for (poll = 0; poll < client->timeout_polls; poll++) {
        uint32_t status = client->bus.read32(client->bus.context, LMS_MMIO_REG_STATUS);
        if ((status & LMS_MMIO_STATUS_BUSY) != 0u) {
            continue;
        }
        if ((status & LMS_MMIO_STATUS_ERROR) != 0u) {
            client->last_hw_error = client->bus.read32(client->bus.context, LMS_MMIO_REG_ERROR);
            return LMS_MMIO_ERR_HARDWARE;
        }
        if ((status & LMS_MMIO_STATUS_DONE) != 0u) {
            if (output && output_len != 0u) {
                read_bytes(&client->bus, LMS_MMIO_REG_OUTPUT, output, output_len);
            }
            if (cycles) {
                *cycles = client->bus.read32(client->bus.context, LMS_MMIO_REG_CYCLE_COUNT);
            }
            client->last_hw_error = 0u;
            return LMS_MMIO_OK;
        }
    }

    return LMS_MMIO_ERR_TIMEOUT;
}

static int wait_for_result(lms_mmio_client_t *client,
                           uint8_t output[LMS_N],
                           uint32_t *cycles)
{
    return wait_for_result_n(client, output, LMS_N, cycles);
}

static int prepare_command(lms_mmio_client_t *client, uint32_t required_capability)
{
    int status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & required_capability) != required_capability) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    client->last_hw_error = 0u;
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_CLEAR);
    if (client->bus.read32(client->bus.context, LMS_MMIO_REG_STATUS) != 0u) {
        return LMS_MMIO_ERR_HARDWARE;
    }
    return LMS_MMIO_OK;
}

int lms_mmio_hash_once(lms_mmio_client_t *client,
                       const uint8_t *input,
                       size_t input_len,
                       uint8_t output[LMS_N],
                       uint32_t *cycles)
{
    uint8_t hardware_output[LMS_N];
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !output || (!input && input_len != 0u)) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (cycles) {
        *cycles = 0u;
    }

    status = prepare_command(client, LMS_MMIO_CAP_HASH_ONCE);
    if (status == LMS_MMIO_OK &&
        input_len > (size_t)client->hash_desc->max_input_bytes) {
        status = LMS_MMIO_ERR_INVALID;
    }
    if (status == LMS_MMIO_OK) {
        client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_HASH_ONCE);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, (uint32_t)input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
        write_bytes(&client->bus, LMS_MMIO_REG_INPUT, input, input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
        status = wait_for_result(client, hardware_output, &command_cycles);
    }
    if (status == LMS_MMIO_OK) {
        memcpy(output, hardware_output, LMS_N);
        /* Independent counter (aligned with chain/derive/keygen/sign/verify): tree hashes such as
         * D_INTR/D_LEAF go through HASH_ONCE via this function, so their hardware cycles must be
         * counted into the LMS-level statistics. */
        client->hardware_hash_once_count++;
        client->hardware_hash_once_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    if (client->allow_fallback &&
        lms_hash(client->hash_desc->hash_alg, input, input_len, output, LMS_N) == 0) {
        client->fallback_count++;
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_hash_once_ram(lms_mmio_client_t *client,
                           const uint8_t *input,
                           size_t input_len,
                           uint8_t output[LMS_N],
                           uint32_t *cycles)
{
    uint8_t hardware_output[LMS_N];
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !output || (!input && input_len != 0u)) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (cycles) {
        *cycles = 0u;
    }

    status = prepare_command(client, LMS_MMIO_CAP_HASH_ONCE);
    if (status == LMS_MMIO_OK &&
        input_len > LMS_MMIO_HASH_ONCE_RAM_MAX) {
        status = LMS_MMIO_ERR_INVALID;
    }
    if (status == LMS_MMIO_OK) {
        client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_HASH_ONCE_RAM);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, (uint32_t)input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
        /* Input is written to task RAM starting at word 32 (RTL HASH_ONCE_RAM read-window base;
         * write side auto-increments) */
        write_task_bytes(&client->bus, 32u, input, input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
        status = wait_for_result(client, hardware_output, &command_cycles);
    }
    if (status == LMS_MMIO_OK) {
        memcpy(output, hardware_output, LMS_N);
        /* Independent counter (aligned with HASH_ONCE): multi-block message-hash cycles count into the LMS-level statistics */
        client->hardware_hash_once_count++;
        client->hardware_hash_once_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    if (client->allow_fallback &&
        lms_hash(client->hash_desc->hash_alg, input, input_len, output, LMS_N) == 0) {
        client->fallback_count++;
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_msg_q_coef(lms_mmio_client_t *client,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        const uint8_t C[LMS_N],
                        const uint8_t *message,
                        size_t message_len,
                        uint32_t lmots_type,
                        uint8_t Q[LMS_N],
                        uint8_t coefficients[LMS_MAX_OTS_P],
                        uint32_t *cycles)
{
    lmots_param_t param;
    uint8_t head[54];                 /* header: I||q little-endian||0x8181||C, written to task RAM word 32 */
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t L;
    uint32_t command_cycles = 0u;
    uint32_t i;
    int status;

    if (!client || !I || !C ||
        (!message && message_len != 0u && message_len <= 74u)) {
        /* message==NULL and m>74: the message is already in task RAM word 46 (level-1 bridge
         * pass-through). Q==NULL: Q is not read back (the keep-mode downstream that leaves the
         * coefficients in hardware does not consume Q, saving 8 MMIO reads). */
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    /* P3 unified task-RAM path (L = 54 + message_len ≤ 2048): the 54B header goes to task RAM
     * word 32, the message to task RAM word 46 (4B-aligned, per the RTL MQC read-window layout;
     * aligned with the HASH_ONCE_RAM header byte order). Over the limit -> protocol error (the
     * caller falls back to software). */
    L = 54u + (uint32_t)message_len;
    if (L > LMS_MMIO_HASH_ONCE_RAM_MAX) {
        return LMS_MMIO_ERR_INVALID;
    }

    status = prepare_command(client, LMS_MMIO_CAP_MSG_Q_COEF);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_MSG_Q_COEF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, L);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, 0u);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    /* Unified task-RAM layout: the 54B header (I||q little-endian||0x8181||C) goes to task RAM
     * word 32, the message to word 46 (4B-aligned, consistent with the RTL MQC read-window layout;
     * aligned with the HASH_ONCE_RAM header byte order). message==NULL (level 1): the message was
     * already written by the bridge pass-through; skipped. */
    memcpy(head, I, LMS_I_LEN);
    head[16] = (uint8_t)q;
    head[17] = (uint8_t)(q >> 8);
    head[18] = (uint8_t)(q >> 16);
    head[19] = (uint8_t)(q >> 24);
    head[20] = 0x81;
    head[21] = 0x81;
    memcpy(head + 22, C, LMS_N);
    /* P3.2: MQC read-window base -- short messages (L≤128) use w = 32+y_words (W4=568/W2=1096/W8=304;
     * W1's y fills 8480B of task RAM with no separate region -> 568); large messages (L>128) fixed at 568 (message 582). */
    uint32_t mqc_base;
    if (L > LMS_MMIO_MAX_INPUT) {
        mqc_base = 568u;
    } else {
        mqc_base = (param.w == 1u) ? 568u : 32u + param.p * 8u;
    }
    write_task_bytes(&client->bus, mqc_base, head, 54u);
    if (message) {
        write_task_bytes(&client->bus, mqc_base + 14u, message, message_len);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);

    /* Q==NULL: skip the output read-back (the keep-mode downstream does not consume Q). */
    status = wait_for_result(client, Q, &command_cycles);
    if (status == LMS_MMIO_OK && coefficients) {
        /* Read back coefficient_words (words 0..; the RTL coefficient region does not auto-increment
         * on read -> per-word ADDR+DATA). nwords = ceil(p*w/32) (SHAKE256 compact packing); the
         * largest W1=265 coefficients = 9 words. coefficients==NULL (P1.5 keep mode) -> coefficients
         * stay in hardware for SIGN/VERIFY reuse. */
        nwords = (param.p * param.w + 31u) / 32u;
        if (nwords > 32u) {
            nwords = 32u;
        }
        for (i = 0u; i < nwords; i++) {
            client->bus.write32(client->bus.context, LMS_MMIO_REG_TASK_ADDR, i);
            packed[i] = client->bus.read32(client->bus.context, LMS_MMIO_REG_TASK_DATA);
        }
        /* Unpack (aligned with the pack_coefficients_words SHAKE256 layout: coefficient i sits in
         * word (i*w)/32 at bit (i*w)%32). */
        for (i = 0u; i < param.p; i++) {
            uint32_t bit = i * param.w;
            uint32_t word = bit / 32u;
            uint32_t shift = bit % 32u;
            uint32_t mask = (param.w == 8u) ? 0xffu : ((1u << param.w) - 1u);
            coefficients[i] = (uint8_t)((packed[word] >> shift) & mask);
        }
    }
    if (status == LMS_MMIO_OK) {
        client->hardware_hash_once_count++;   /* message hash (incl. checksum/coef) counts into hash_once */
        client->hardware_hash_once_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_chain(lms_mmio_client_t *client,
                   const uint8_t I[LMS_I_LEN],
                   uint32_t q,
                   uint32_t i,
                   uint32_t start,
                   uint32_t steps,
                   uint8_t value[LMS_N],
                   uint32_t *cycles)
{
    uint8_t hardware_output[LMS_N];
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !value || i > UINT16_MAX || start > UINT8_MAX ||
        steps > UINT8_MAX || start + steps > UINT8_MAX) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (cycles) {
        *cycles = 0u;
    }

    status = prepare_command(client, LMS_MMIO_CAP_CHAIN);
    if (status == LMS_MMIO_OK) {
        client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_CHAIN);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_I, i);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_START, start);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_STEPS, steps);
        write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
        write_bytes(&client->bus, LMS_MMIO_REG_INPUT, value, LMS_N);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
        status = wait_for_result(client, hardware_output, &command_cycles);
    }
    if (status == LMS_MMIO_OK) {
        memcpy(value, hardware_output, LMS_N);
        client->hardware_chain_count++;
        client->hardware_chain_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    if (client->allow_fallback &&
        lmots_chain_compute(I, client->hash_desc->hash_alg, q, i, start, steps, value) == LMS_OK) {
        client->fallback_count++;
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_seed_load_test(lms_mmio_client_t *client,
                            uint32_t key_handle,
                            const uint8_t seed[LMS_SEED_LEN])
{
    int status;

    if (!client || !seed || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_DERIVE_CHAIN |
                                     LMS_MMIO_CAP_INSECURE_TEST_MODE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_SEED_LOAD);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    write_bytes(&client->bus, LMS_MMIO_REG_SEED, seed, LMS_SEED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    {
        uint32_t ignored_cycles;
        uint8_t ignored_output[LMS_N];
        return wait_for_result(client, ignored_output, &ignored_cycles);
    }
}

/* Controlled SEED load (0.1.281, deploy model B): the only on-device path for a new SEED into
 * hardware slot 0 under deploy (INSECURE_TEST_MODE=0). The SEED is generated on-device by the
 * **on-device TRNG** (called from firmware internally) and enters the slot via CMD_SEED_WRITE_SAFE
 * (not in the UART request table) -- the plaintext SEED_LOAD gating is unchanged.
 * Requires CAP_WRAP (security-domain build); test configurations also allow it (equivalent to
 * seed_load_test but without needing CAP_INSECURE_TEST_MODE). */
int lms_mmio_seed_load_safe(lms_mmio_client_t *client,
                            const uint8_t seed[LMS_SEED_LEN])
{
    int status;

    if (!client || !seed) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_WRAP);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_SEED_WRITE_SAFE);
    write_bytes(&client->bus, LMS_MMIO_REG_SEED, seed, LMS_SEED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    {
        uint32_t ignored_cycles;
        uint8_t ignored_output[LMS_N];
        return wait_for_result(client, ignored_output, &ignored_cycles);
    }
}

int lms_mmio_mc_read(lms_mmio_client_t *client, uint32_t *value)
{
    int status;

    if (!client || !value) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & LMS_MMIO_CAP_SIM_MC) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }
    *value = client->bus.read32(client->bus.context, LMS_MMIO_REG_SIM_MC);
    return LMS_MMIO_OK;
}

int lms_mmio_mc_step(lms_mmio_client_t *client, uint32_t *value)
{
    uint8_t output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_SIM_MC);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_MC_STEP);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &cycles);
    if (status == LMS_MMIO_OK && value) {
        /* The new value is in output_words[0], little-endian. */
        *value = (uint32_t)output[0] | ((uint32_t)output[1] << 8) |
                 ((uint32_t)output[2] << 16) | ((uint32_t)output[3] << 24);
    }
    return status;
}

int lms_mmio_state_commit(lms_mmio_client_t *client,
                          uint16_t new_state, uint32_t ctr, uint8_t aad,
                          uint32_t *tx_out, uint8_t tag[16])
{
    uint8_t output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client || !tx_out || !tag) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_SIM_MC | LMS_MMIO_CAP_HMAC_KSTATE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    /* The body fields go through the ARG registers: ARG_I=state, ARG_Q=ctr, ARG_KEY=aad(slot_id).
     * magic/tx/reserved are constructed by hardware (tx=sim_mc+1 hardware monotonic). */
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_I, new_state);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, ctr);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, aad);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_STATE_COMMIT);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    /* F5: STATE_COMMIT only needs tx (1 word) + tag (4 words) = 5 words; read only 20B as needed
     * (saves 3 read32 + 12 byte stores; the 8-word output region supports arbitrary prefix reads). */
    status = wait_for_result_n(client, output, 20u, &cycles);
    if (status == LMS_MMIO_OK) {
        /* word0=tx (little-endian), words 1..4=tag (first 16B) */
        *tx_out = (uint32_t)output[0] | ((uint32_t)output[1] << 8) |
                  ((uint32_t)output[2] << 16) | ((uint32_t)output[3] << 24);
        memcpy(tag, output + 4, 16u);
    }
    return status;
}

int lms_mmio_mc_load(lms_mmio_client_t *client, uint32_t value)
{
    uint8_t output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_SIM_MC);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_MC_LOAD);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, value);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    return wait_for_result(client, output, &cycles);
}

int lms_mmio_key_slot_load_test(lms_mmio_client_t *client,
                                uint32_t key_slot,
                                const uint8_t key[LMS_SEED_LEN])
{
    uint32_t base;
    int status;

    if (!client || !key || (key_slot != LMS_MMIO_KEY_KWRAP && key_slot != LMS_MMIO_KEY_KSTATE)) {
        return LMS_MMIO_ERR_INVALID;
    }
    /* K_WRAP/K_STATE share the KWRAP staging window (arg_key selects the latch target);
     * K_STATE's proper path is the KDF (step 4); this test interface mainly serves K_WRAP. */
    base = LMS_MMIO_REG_KWRAP;
    status = prepare_command(client, LMS_MMIO_CAP_WRAP |
                                     LMS_MMIO_CAP_INSECURE_TEST_MODE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_SEED_LOAD);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_slot);
    write_bytes(&client->bus, base, key, LMS_SEED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    {
        uint32_t ignored_cycles;
        uint8_t ignored_output[LMS_N];
        return wait_for_result(client, ignored_output, &ignored_cycles);
    }
}

int lms_mmio_wrap_seed(lms_mmio_client_t *client,
                       uint8_t wrapped[LMS_MMIO_WRAPPED_LEN])
{
    uint8_t ignored_output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client || !wrapped) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_WRAP);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_WRAP_SEED);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, ignored_output, &cycles);
    if (status == LMS_MMIO_OK) {
        read_bytes(&client->bus, LMS_MMIO_REG_WRAPPED, wrapped, LMS_MMIO_WRAPPED_LEN);
    }
    return status;
}

int lms_mmio_unwrap_seed(lms_mmio_client_t *client,
                         const uint8_t wrapped[LMS_MMIO_WRAPPED_LEN])
{
    uint8_t ignored_output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client || !wrapped) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_WRAP);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    write_bytes(&client->bus, LMS_MMIO_REG_WRAPPED, wrapped, LMS_MMIO_WRAPPED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_UNWRAP_SEED);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    return wait_for_result(client, ignored_output, &cycles);
}

int lms_mmio_hmac_kstate(lms_mmio_client_t *client,
                         const uint8_t *input,
                         size_t input_len,
                         uint8_t output[LMS_N])
{
    uint32_t cycles;
    int status;

    if (!client || !output || (!input && input_len != 0u) || input_len > 119u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_HMAC_KSTATE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_HMAC_KSTATE);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, (uint32_t)input_len);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
    write_bytes(&client->bus, LMS_MMIO_REG_INPUT, input, input_len);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    return wait_for_result(client, output, &cycles);
}

int lms_mmio_derive_chain(lms_mmio_client_t *client,
                          uint32_t key_handle,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t i,
                          uint32_t start,
                          uint32_t steps,
                          uint8_t output[LMS_N],
                          uint32_t *cycles)
{
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u || i > UINT16_MAX ||
        start > UINT8_MAX || steps > UINT8_MAX || start + steps > UINT8_MAX) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_DERIVE_CHAIN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_DERIVE_CHAIN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_I, i);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_START, start);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_STEPS, steps);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_derive_count++;
        client->hardware_derive_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_derive_randomizer(lms_mmio_client_t *client,
                               uint32_t key_handle,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint8_t output[LMS_N],
                               uint32_t *cycles)
{
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_DERIVE_CHAIN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_DERIVE_RANDOMIZER);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_derive_count++;
        client->hardware_derive_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_keygen(lms_mmio_client_t *client,
                          uint32_t key_handle,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t lmots_type,
                          uint8_t output[LMS_N],
                          uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_KEYGEN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_KEYGEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_keygen_count++;
        client->hardware_keygen_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_keygen_leaf(lms_mmio_client_t *client,
                                uint32_t key_handle,
                                const uint8_t I[LMS_I_LEN],
                                uint32_t q,
                                uint32_t node_num,
                                uint32_t lmots_type,
                                uint8_t output[LMS_N],
                                uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_KEYGEN_LEAF);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_KEYGEN_LEAF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_LEAF_NODE, node_num);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_keygen_count++;
        client->hardware_keygen_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_sign(lms_mmio_client_t *client,
                        uint32_t key_handle,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        uint32_t lmots_type,
                        const uint8_t coefficients[LMS_MAX_OTS_P],
                        uint8_t outputs[LMS_MAX_OTS_P * LMS_N],
                        uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0 = soc_cycle_count();
#endif

    if (!client || !I || !outputs || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;
    /* coefficients==NULL (P1.5 coef_ready) -> coefficients already in hardware coefficient_words; skip packing + write */
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_SIGN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_SIGN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t1 = soc_cycle_count();
#endif
    status = wait_for_result(client, NULL, &command_cycles);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t2 = soc_cycle_count();
#endif
    if (status == LMS_MMIO_OK) {
        read_task_bytes(&client->bus, LMS_MMIO_TASK_CHAIN_WORD_BASE,
                        outputs, chain_bytes);
#if defined(LMS_MMIO_SOC_PROFILE)
        uint32_t prof_t3 = soc_cycle_count();
        client->prof_write_cycles = prof_t1 - prof_t0;
        client->prof_wait_cycles = prof_t2 - prof_t1;
        client->prof_read_cycles = prof_t3 - prof_t2;
#endif
        client->hardware_sign_count++;
        client->hardware_sign_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

/* UART bridge variant: the signature stays in task RAM (no read-back); the SoC-layer UART pass-through bridge reads it out. */
int lms_mmio_lmots_sign_taskram(lms_mmio_client_t *client,
                                uint32_t key_handle,
                                const uint8_t I[LMS_I_LEN],
                                uint32_t q,
                                uint32_t lmots_type,
                                const uint8_t coefficients[LMS_MAX_OTS_P],
                                uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0 = soc_cycle_count();
#endif

    if (!client || !I || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;
    /* coefficients==NULL (P1.5 coef_ready) -> coefficients already in hardware coefficient_words */
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_SIGN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_SIGN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t1 = soc_cycle_count();
#endif
    status = wait_for_result(client, NULL, &command_cycles);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t2 = soc_cycle_count();
    client->prof_write_cycles = prof_t1 - prof_t0;
    client->prof_wait_cycles = prof_t2 - prof_t1;
    client->prof_read_cycles = 0u;
#endif
    if (status == LMS_MMIO_OK) {
        client->hardware_sign_count++;
        client->hardware_sign_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_verify(lms_mmio_client_t *client,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t coefficients[LMS_MAX_OTS_P],
                          const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                          uint8_t output[LMS_N],
                          uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0 = soc_cycle_count();
#endif

    if (!client || !I || !inputs || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;
    /* coefficients==NULL (P1.5 coef_ready) -> coefficients already in hardware coefficient_words */
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    write_task_bytes(&client->bus, LMS_MMIO_TASK_CHAIN_WORD_BASE,
                     inputs, chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t1 = soc_cycle_count();
#endif
    status = wait_for_result(client, output, &command_cycles);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t2 = soc_cycle_count();
    client->prof_write_cycles = prof_t1 - prof_t0;
    client->prof_wait_cycles = prof_t2 - prof_t1;
    client->prof_read_cycles = 0u;
#endif
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

/* UART bridge variant: the signature y has already been written to task RAM by the SoC-layer UART pass-through bridge (skips write_task_bytes) */
int lms_mmio_lmots_verify_taskram(lms_mmio_client_t *client,
                                  const uint8_t I[LMS_I_LEN],
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t coefficients[LMS_MAX_OTS_P],
                                  uint8_t output[LMS_N],
                                  uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    /* coefficients==NULL (P1.5 coef_ready) -> coefficients already in hardware coefficient_words */
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_verify_leaf(lms_mmio_client_t *client,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint32_t node_num,
                               uint32_t lmots_type,
                               const uint8_t coefficients[LMS_MAX_OTS_P],
                               const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                               uint8_t output[LMS_N],
                               uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !inputs || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;
    /* coefficients==NULL (P1.5 coef_ready) -> coefficients already in hardware coefficient_words */
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    write_task_bytes(&client->bus, LMS_MMIO_TASK_CHAIN_WORD_BASE,
                     inputs, chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY_LEAF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_LEAF_NODE, node_num);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

/* UART bridge variant: the signature y has already been written to task RAM by the SoC-layer
 * UART pass-through bridge (skips the inputs transfer). VERIFY_LEAF semantics: chain verification
 * -> K_q -> D_LEAF, outputting only the leaf node. */
int lms_mmio_lmots_verify_leaf_taskram(lms_mmio_client_t *client,
                                       const uint8_t I[LMS_I_LEN],
                                       uint32_t q,
                                       uint32_t node_num,
                                       uint32_t lmots_type,
                                       const uint8_t coefficients[LMS_MAX_OTS_P],
                                       uint8_t output[LMS_N],
                                       uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    /* coefficients==NULL (P1.5 coef_ready) -> coefficients already in hardware coefficient_words */
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY_LEAF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_LEAF_NODE, node_num);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

static int lmots_mmio_sign(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t q,
                           uint32_t lmots_type,
                           const uint8_t *coefficients,
                           uint8_t *outputs)
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {
        /* P1.5: coefficients already in hardware coefficient_words; skip packing + write */
        client->coef_ready = 0;
        return lms_mmio_lmots_sign(client, client->key_handle, I, q, lmots_type,
                                   NULL, outputs, NULL) == LMS_MMIO_OK
            ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_sign(client, client->key_handle, I, q, lmots_type,
                               coefficients, outputs, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_verify(void *context,
                             const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg,
                             uint32_t q,
                             uint32_t lmots_type,
                             const uint8_t *coefficients,
                             const uint8_t *inputs,
                             uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {
        /* P1.5: coefficients already in hardware coefficient_words; skip packing + write */
        client->coef_ready = 0;
        return lms_mmio_lmots_verify(client, I, q, lmots_type,
                                     NULL, inputs, output, NULL) == LMS_MMIO_OK
            ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_verify(client, I, q, lmots_type, coefficients,
                                 inputs, output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_keygen(void *context,
                             const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg,
                             uint32_t q,
                             uint32_t lmots_type,
                             uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_keygen(client, client->key_handle, I, q, lmots_type,
                                 output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

/* Randomizer C source (TRNG-C scheme, scheme A: backend reads directly; decided in session
 * 2026-08-22). The hardware CMD_DERIVE_RANDOMIZER is no longer called (deterministic
 * C=H(I‖q‖0x8585‖SEED)); instead the firmware decides via the client fields configured by
 * INSECURE_TEST_MODE:
 *   - debug (INSECURE_TEST_MODE=1): randomizer_c_slot points to the fixed 32B test vector loaded
 *     into C_LOAD(0x6C) -> direct copy (deterministic signature; reproducible for KAT/TVLA).
 *   - deploy (INSECURE_TEST_MODE=0): trng_fill_c reads 32B from the security-domain TRNG
 *     (health-gated fail-closed, no external injection path) -> RFC 8554 standard randomizer.
 * Priority: slot > trng > error. */
static int lmots_mmio_get_randomizer_c(lms_mmio_client_t *client,
                                       const uint8_t I[LMS_I_LEN],
                                       uint32_t q,
                                       uint8_t output[LMS_N])
{
    if (client->randomizer_c_slot != NULL) {
        memcpy(output, client->randomizer_c_slot, LMS_N);
        return LMS_OK;
    }
    if (client->trng_fill_c != NULL) {
        return client->trng_fill_c(client->trng_context, output) == 0 ? LMS_OK : LMS_ERR_INVALID;
    }
    /* Not explicitly configured (host/PC unit tests etc.): fall back to the hardware deterministic
     * DERIVE_RANDOMIZER (kept for diagnostics). Real deploy/debug paths always have firmware set
     * randomizer_c_slot (debug) or trng_fill_c (deploy) explicitly, so they never reach this
     * fallback. Host unit tests without a source still use the old deterministic C to keep the
     * expected values. */
    return lms_mmio_derive_randomizer(client, 0u, I, q, output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_randomizer(void *context,
                                 const uint8_t I[LMS_I_LEN],
                                 lms_hash_alg_t hash_alg,
                                 uint32_t q,
                                 uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lmots_mmio_get_randomizer_c(client, I, q, output);
}

int lms_mmio_lmots_keygen_enable(lms_mmio_client_t *client, uint32_t key_handle)
{
    int status;
    if (!client || client->allow_fallback || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK ||
        (client->capabilities & LMS_MMIO_CAP_LMOTS_KEYGEN) == 0u) {
        return status != LMS_MMIO_OK ? status : LMS_MMIO_ERR_PROTOCOL;
    }
    client->key_handle = key_handle;
    lmots_keygen_backend_set(lmots_mmio_keygen, client);
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_sign_enable(lms_mmio_client_t *client, uint32_t key_handle)
{
    int status;
    if (!client || client->allow_fallback || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK ||
        (client->capabilities & (LMS_MMIO_CAP_DERIVE_CHAIN |
                                LMS_MMIO_CAP_LMOTS_SIGN)) !=
            (LMS_MMIO_CAP_DERIVE_CHAIN | LMS_MMIO_CAP_LMOTS_SIGN)) {
        return status != LMS_MMIO_OK ? status : LMS_MMIO_ERR_PROTOCOL;
    }
    client->key_handle = key_handle;
    lmots_sign_backend_set(lmots_mmio_sign, client);
    lmots_sign_randomizer_backend_set(lmots_mmio_randomizer, client);
    return LMS_MMIO_OK;
}

static int lmots_mmio_chain(void *context,
                            const uint8_t I[LMS_I_LEN],
                            lms_hash_alg_t hash_alg,
                            uint32_t q,
                            uint32_t i,
                            uint32_t start,
                            uint32_t steps,
                            uint8_t value[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;

    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lms_mmio_chain(client, I, q, i, start, steps, value, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

/* sign_derive_backend wrapper: the hardware DERIVE_CHAIN does the full sequence from the
 * internal SEED slot (derive x=H(I‖q‖i‖0xff‖SEED) + chain H^steps(x)), replacing the software
 * lmots_private_value. The SEED must first be loaded into hardware slot 0 via
 * lms_mmio_seed_load_test. */
static int lmots_mmio_sign_derive(void *context,
                                   const uint8_t I[LMS_I_LEN],
                                   lms_hash_alg_t hash_alg,
                                   uint32_t q,
                                   uint32_t i,
                                   uint32_t start,
                                   uint32_t steps,
                                   uint8_t value[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;

    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lms_mmio_derive_chain(client, 0u, I, q, i, start, steps, value, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

/* sign_randomizer_backend wrapper: the C source is decided by the client fields (see the
 * lmots_mmio_get_randomizer_c note above). No longer uses the hardware DERIVE_RANDOMIZER. */
static int lmots_mmio_sign_randomizer(void *context,
                                       const uint8_t I[LMS_I_LEN],
                                       lms_hash_alg_t hash_alg,
                                       uint32_t q,
                                       uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;

    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lmots_mmio_get_randomizer_c(client, I, q, output);
}

int lms_mmio_lmots_keygen_enable_insecure(lms_mmio_client_t *client)
{
    int status;

    if (!client || client->allow_fallback) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & LMS_MMIO_CAP_CHAIN) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    lmots_keygen_chain_backend_set(lmots_mmio_chain, client);
    if ((client->capabilities & LMS_MMIO_CAP_DERIVE_CHAIN) != 0u) {
        lmots_keygen_derive_backend_set(lmots_mmio_sign_derive, client);
    }
    if ((client->capabilities & LMS_MMIO_CAP_LMOTS_KEYGEN) != 0u) {
        /* fused keygen_backend: one MMIO call completes all 67 chains (W4), returning the K_q
         * public key directly. Replaces 67 separate DERIVE_CHAIN calls. */
        lmots_keygen_backend_set(lmots_mmio_keygen, client);
    }
    return LMS_MMIO_OK;
}

void lms_mmio_lmots_keygen_disable(void)
{
    lmots_keygen_chain_backend_set(NULL, NULL);
    lmots_keygen_derive_backend_set(NULL, NULL);
    lmots_keygen_backend_set(NULL, NULL);
}

int lms_mmio_lmots_verify_enable(lms_mmio_client_t *client)
{
    int status;

    if (!client || client->allow_fallback) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & (LMS_MMIO_CAP_CHAIN |
                                LMS_MMIO_CAP_LMOTS_VERIFY)) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    if ((client->capabilities & LMS_MMIO_CAP_LMOTS_VERIFY) != 0u) {
        lmots_verify_backend_set(lmots_mmio_verify, client);
    } else {
        lmots_verify_chain_backend_set(lmots_mmio_chain, client);
    }
    return LMS_MMIO_OK;
}

void lms_mmio_lmots_verify_disable(void)
{
    lmots_verify_chain_backend_set(NULL, NULL);
    lmots_verify_backend_set(NULL, NULL);
}

int lms_mmio_lmots_sign_enable_insecure(lms_mmio_client_t *client)
{
    int status;

    if (!client || client->allow_fallback) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & LMS_MMIO_CAP_CHAIN) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    lmots_sign_chain_backend_set(lmots_mmio_chain, client);
    if ((client->capabilities & LMS_MMIO_CAP_DERIVE_CHAIN) != 0u) {
        lmots_sign_derive_backend_set(lmots_mmio_sign_derive, client);
        lmots_sign_randomizer_backend_set(lmots_mmio_sign_randomizer, client);
    }
    if ((client->capabilities & LMS_MMIO_CAP_LMOTS_SIGN) != 0u) {
        /* fused sign_backend: one MMIO call completes all 67 chains, replacing 67 separate
         * DERIVE_CHAIN calls. sign_backend has the highest priority; once hit, the per-coef loop
         * is bypassed. */
        lmots_sign_backend_set(lmots_mmio_sign, client);
    }
    return LMS_MMIO_OK;
}

void lms_mmio_lmots_sign_disable(void)
{
    lmots_sign_chain_backend_set(NULL, NULL);
    lmots_sign_derive_backend_set(NULL, NULL);
    lmots_sign_randomizer_backend_set(NULL, NULL);
    lmots_sign_backend_set(NULL, NULL);
}