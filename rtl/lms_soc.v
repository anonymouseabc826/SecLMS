`include "lms_soc_config.vh"

module lms_soc #(
    parameter FIRMWARE_HEX = "",
    parameter INSECURE_TEST_MODE = 0,
    parameter TRNG_SIM_MODE = 0,
    parameter ENABLE_SHA256   = `LMS_SOC_ENABLE_SHA256,
    parameter ENABLE_SHAKE256 = `LMS_SOC_ENABLE_SHAKE256,
    parameter HAS_SECURITY    = `LMS_SOC_HAS_SECURITY,
    parameter SCA_TEST        = 0,       /* 1=enable SCA trigger output (for TVLA, off by default) */
    parameter RANDOM_DELAY    = 0,       /* TVLA light mitigation: LFSR random delay before 0x6D DERIVE (enabled in TVLA builds) */
    parameter DERIVE_SHUFFLE  = 0,       /* DERIVE phase shuffle: random start offset of batch task block parameters per trace (enabled in TVLA builds) */
    parameter ALLOW_XQ_DERIVE = 0        /* TVLA isolated single x_q[i] release (see plan; deploy defaults 0 to keep M3) */
) (
    input  wire       clk,
    input  wire       rst,
    input  wire       uart_rxd,
    output wire       uart_txd,
    input  wire       uart_cts_i,       /* external RTS flow control (CW305 bridge TX FIFO full pulls low to pause) */
    input  wire [7:0] gpio_in,
    output reg  [7:0] gpio_out,
    output wire       trap,
    output wire       sca_trigger,      /* SCA trigger (active when SCA_TEST=1, see below) */
    /* SPI flash peripheral (M1 access verification, CW305 on-board SPI NOR) */
    output wire       spi_sck,          /* -> STARTUPE2 USRCCLKO (flash SCK) */
    output wire       spi_sck_en,       /* 1=drive CCLK (USRCCLKTS=0) */
    output wire       spi_cs_n,         /* -> flash CS (L12) */
    output wire       spi_mosi,         /* -> flash SI (J13) */
    input  wire [4:0] spi_miso          /* flash SO candidates: [0]=B4 [1]=K12 [2]=J14 [3]=K15 [4]=L13 */
);
    localparam [31:0] MMIO_BASE = 32'h1000_0000;
    localparam [31:0] LMS_BASE = 32'h1600_0000;
    localparam [31:0] TRNG_BASE = 32'h1700_0000;
    localparam [31:0] BRIDGE_BASE = 32'h1800_0000;   /* UART<->task RAM pass-through bridge (Step 3) */
    localparam [31:0] FLASH_BASE = 32'h1900_0000;    /* SPI flash peripheral (M1) */
    localparam integer RAM_WORD_XADR = `LMS_SOC_RAM_XADR - 2;
    localparam integer RAM_WORDS = 1 << RAM_WORD_XADR;
    localparam integer UART_BITCLKS = `LMS_SOC_CLK / 115200;

    localparam [2:0] RDATA_NONE = 3'd0;
    localparam [2:0] RDATA_RAM = 3'd1;
    localparam [2:0] RDATA_MMIO = 3'd2;
    localparam [2:0] RDATA_LMS = 3'd3;
    localparam [2:0] RDATA_TRNG = 3'd4;
    localparam [2:0] RDATA_BRIDGE = 3'd5;
    localparam [2:0] RDATA_FLASH = 3'd6;

    (* ASYNC_REG = "TRUE" *) reg [1:0] reset_sync;
    wire reset = reset_sync[1];

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            reset_sync <= 2'b11;
        end else begin
            reset_sync <= {reset_sync[0], 1'b0};
        end
    end

    wire        mem0_valid;
    wire [31:0] mem0_addr;
    wire [31:0] mem0_wdata;
    wire [3:0]  mem0_wstrb;
    wire [31:0] mem0_rdata;
    wire [31:0] mem1_addr;
    wire [31:0] mem1_rdata;
    wire        instr_req;
    reg         instr_req_d;
    reg         instr_rvalid;
    reg  [RAM_WORD_XADR-1:0] instr_addr_q;
    reg         data_rvalid;
    wire        ibex_data_we;
    wire [3:0]  ibex_data_be;
    wire        alert_major_internal;
    wire        alert_major_bus;
    wire        lms_req;
    reg         lms_bus_valid;
    reg         lms_bus_read;
    reg         lms_bus_read_wait;
    reg  [31:0] lms_bus_addr;
    reg  [31:0] lms_bus_wdata;
    reg  [3:0]  lms_bus_wstrb;
    reg         ram_req_pending;
    reg  [RAM_WORD_XADR-1:0] ram_addr_q;
    reg  [31:0] ram_wdata_q;
    reg  [3:0]  ram_wen_q;

    assign mem0_wstrb = ibex_data_we ? ibex_data_be : 4'b0000;
    assign trap = alert_major_internal | alert_major_bus;
    /* LMS window 2KB ([31:11], REVIEW G-M8 fix): inside the shell, split by bus_addr[10] into SHA-256
     * 0x000-0x3FF / SHAKE256 0x400-0x7FF; previously [31:10] (1KB) blocked the SHAKE segment at the
     * SoC level, making the SHAKE register window unreachable in both dual-hash builds. */
    assign lms_req = !reset && mem0_valid &&
                     mem0_addr[31:11] == LMS_BASE[31:11];

    /* SCA trigger (for TVLA side-channel evaluation, finalized v3 on 2026-08-17, changed to v5 on 2026-08-18):
     *  - Trigger point = engine busy falling edge (completion edge; stream_busy: SHAKE256 wrapper's
     *    wrapper_busy = engine busy || FSM not IDLE || secure domain busy).
     *    v1 used the "LMS window CONTROL(0x00c) START bit write edge", requiring combinational comparison of mem0_addr/
     *    mem0_wdata (ibex data bus) -- with SCA_TEST=1 that combinational load really exists,
     *    RV32 has no icache, layout-sensitive (DEAD countermeasure known) -> the firmware MMIO read-digest path
     *    timing margin worsened; on the board, digest intermittently flipped bit5 (0x52->0x72, b9->99, etc.).
     *    v2 changed to reading stream_busy (engine status output, zero data-bus load) -> digest recovered,
     *    but a 1-cycle (20ns) trigger pulse was too narrow: Husky TIO4 trigger through the synchronizer (>=2 sampling
     *    periods) missed samples (all board captures timed out).
     *    v3/v4: busy rising edge sets a wide pulse -- trigger = engine start, but the 512-cycle pulse
     *    (@15.6MHz ~= 33us) covers the DERIVE at the operation start (direct PRF leak point), cannot focus.
     *    v5 (2026-08-18 option 1): changed to busy falling edge (completion edge) trigger -- Husky uses
     *    presamples (up to 32767 samples ~= 655us@50MS/s) to cover the whole operation (including the leading
     *    DERIVE/PRF segment), wide pulse moved out of the operation window. Satisfies memory.md section 12
     *    "aligned with hardware cycles, decoupled from crypto computation control" (trigger still strictly bound
     *    to busy state, only the phase moves from the start edge to the completion edge).
     *  - SCA_TEST=0 (default/deploy) constant 0: test interface can be compiled out, not in the deploy bitstream. */
    reg  stream_busy_d;
    reg  [8:0] sca_pulse_cnt;   /* 9 bits: pulse 512 cycles (@15.6MHz ~= 33us / @5MHz ~= 102us),
                                   ensuring Husky TIO4 detects it under CW305's actual clock (2026-08-18:
                                   original 32 cycles was only 2.05us at 15.6MHz, Husky trigger timeout) */
    always @(posedge clk) begin
        if (reset) begin
            stream_busy_d <= 1'b0;
            sca_pulse_cnt <= 9'd0;
        end else begin
            stream_busy_d <= stream_busy;
            if (stream_busy && !stream_busy_d) begin
                /* Trigger edge = busy rising edge (start edge) (2026-08-19 scheme B-RTL fix):
                 * with the completion edge (v5-v10), the engine's internal random delay follows the trigger (trigger = DERIVE
                 * completion point), trace-internal phase unchanged -> randomization ineffective. Rising-edge trigger = fixed
                 * operation start point; the engine's internal random delay (0x6D specific) makes DERIVE phase random relative to the trigger -> thins leakage per point t. */
                sca_pulse_cnt <= 9'd511;     /* busy rising edge (start edge): set a 512-cycle wide pulse */
            end else if (sca_pulse_cnt != 9'd0) begin
                sca_pulse_cnt <= sca_pulse_cnt - 9'd1;
            end
        end
    end
    assign sca_trigger = SCA_TEST ? (sca_pulse_cnt != 9'd0) : 1'b0;

    ibex_top #(
        .PMPEnable(1'b0),
        .RV32M(ibex_pkg::RV32MSingleCycle),
        .RV32B(ibex_pkg::RV32BNone),
        .RegFile(ibex_pkg::RegFileFF),
        .BranchTargetALU(1'b1),
        .WritebackStage(1'b1),
        .ICache(1'b0),
        .ICacheECC(1'b0),
        .ICacheScramble(1'b0),
        .BranchPredictor(1'b0),
        .DbgTriggerEn(1'b0),
        .SecureIbex(1'b0)
    ) cpu (
        .clk_i(clk),
        .rst_ni(~reset),
        .test_en_i(1'b0),
        .ram_cfg_i('0),
        .hart_id_i(32'b0),
        .boot_addr_i(32'b0),
        .instr_req_o(instr_req),
        .instr_gnt_i(instr_req),
        .instr_rvalid_i(instr_rvalid),
        .instr_addr_o(mem1_addr),
        .instr_rdata_i(mem1_rdata),
        .instr_rdata_intg_i(7'b0),
        .instr_err_i(1'b0),
        .data_req_o(mem0_valid),
        .data_gnt_i(mem0_valid),
        .data_rvalid_i(data_rvalid),
        .data_we_o(ibex_data_we),
        .data_be_o(ibex_data_be),
        .data_addr_o(mem0_addr),
        .data_wdata_o(mem0_wdata),
        .data_wdata_intg_o(),
        .data_rdata_i(mem0_rdata),
        .data_rdata_intg_i(7'b0),
        .data_err_i(1'b0),
        .irq_software_i(1'b0),
        .irq_timer_i(1'b0),
        .irq_external_i(1'b0),
        .irq_fast_i(15'b0),
        .irq_nm_i(1'b0),
        .scramble_key_valid_i(1'b0),
        .scramble_key_i('0),
        .scramble_nonce_i('0),
        .scramble_req_o(),
        .debug_req_i(1'b0),
        .crash_dump_o(),
        .double_fault_seen_o(),
        .fetch_enable_i(ibex_pkg::IbexMuBiOn),
        .alert_minor_o(),
        .alert_major_internal_o(alert_major_internal),
        .alert_major_bus_o(alert_major_bus),
        .core_sleep_o(),
        .scan_rst_ni(1'b1)
    );

    always @(posedge clk) begin
        if (reset) begin
            instr_req_d <= 1'b0;
            instr_rvalid <= 1'b0;
            instr_addr_q <= {RAM_WORD_XADR{1'b0}};
        end else begin
            instr_req_d <= instr_req;
            instr_rvalid <= instr_req_d;
            if (instr_req) begin
                instr_addr_q <= mem1_addr[`LMS_SOC_RAM_XADR-1:2];
            end
        end
    end

    wire ram_sel = !reset && mem0_valid && mem0_addr[31:`LMS_SOC_RAM_XADR] == 0;
    wire [31:0] ram_rdata;

    lms_fpga_ram #(
        .XADR(RAM_WORD_XADR),
        .XSIZ(RAM_WORDS),
        .FIRMWARE_HEX(FIRMWARE_HEX)
    ) ram (
        .clk(clk),
        .wen0(ram_wen_q),
        .addr0(ram_addr_q),
        .wdata0(ram_wdata_q),
        .rdata0(ram_rdata),
        .addr1(instr_addr_q),
        .rdata1(mem1_rdata)
    );

    /* REVIEW B11B12-R3 (2026-08-17 hardening): decode window [31:24](16MB)->[31:8](256B),
     * eliminating the register alias surface caused by unchecked [23:8] (0x1000_0100..0x10FF_FFFF used to silently
     * alias to the same group of 7 registers); register decode is still [7:2], undefined offsets fall to default 0. */
    wire mmio_sel = !reset && mem0_valid && mem0_addr[31:8] == MMIO_BASE[31:8];
    reg [31:0] cycle_count;
    reg [31:0] mmio_rdata;
    reg [7:0] uart_tx_data;
    reg uart_tx_send;
    wire uart_tx_ready;
    wire [7:0] uart_rx_data;
    wire uart_rx_ready;
    reg uart_rx_ack;
    /* UART<->task RAM pass-through bridge (Step 3): bypass UART only after the CPU writes bridge START.
     * Do not use bridge_busy directly to control the mux, to avoid an implementation anomaly or reset residue permanently blocking the CPU UART. */
    wire        bridge_rx_ack;
    wire [7:0]  bridge_tx_data;
    wire        bridge_tx_send;
    wire        bridge_busy;
    reg         bridge_owner;
    wire        bridge_start_req = !reset && mem0_valid && ibex_data_we &&
                                   mem0_addr == BRIDGE_BASE && mem0_wstrb[0] &&
                                   mem0_wdata[0];
    wire        bridge_active = bridge_owner;
    wire        uart_rx_ack_eff = bridge_active ? bridge_rx_ack : uart_rx_ack;
    wire        uart_tx_send_eff = bridge_active ? bridge_tx_send : uart_tx_send;
    wire [7:0]  uart_tx_data_eff = bridge_active ? bridge_tx_data : uart_tx_data;

    always @(posedge clk) begin
        if (reset) begin
            bridge_owner <= 1'b0;
        end else if (bridge_start_req) begin
            bridge_owner <= 1'b1;
        end else if (bridge_owner && !bridge_busy) begin
            bridge_owner <= 1'b0;
        end
    end

    uart_tx #(
        .BITCLKS(UART_BITCLKS)
    ) uart_tx_unit (
        .clk(clk),
        .rst(reset),
        .send(uart_tx_send_eff),
        .data(uart_tx_data_eff),
        .rdy(uart_tx_ready),
        .cts(uart_cts_i),   /* 2026-08-19: external RTS flow control (was 1'b1 without flow control, CW305 pass-through y hung) */
        .txd(uart_txd)
    );

    uart_rx #(
        .BITCLKS(UART_BITCLKS)
    ) uart_rx_unit (
        .clk(clk),
        .rst(reset),
        .ack(uart_rx_ack_eff),
        .data(uart_rx_data),
        .rdy(uart_rx_ready),
        .rts(),
        .rxd(uart_rxd)
    );

    /* GPIO input two-stage synchronization (REVIEW B11B12-R5): gpio_in is an asynchronous board-level input; the original
     * implementation sampled it combinationally into mmio_rdata (no synchronizer); two FFs eliminate metastability. The top
     * level currently hard-wires 0; defensive hardening, behavior unchanged. */
    (* ASYNC_REG = "TRUE" *) reg [7:0] gpio_in_sync1;   /* REVIEW B11B12-R6 same kind: synchronizer ASYNC_REG */
    (* ASYNC_REG = "TRUE" *) reg [7:0] gpio_in_sync2;
    always @(posedge clk) begin
        if (reset) begin
            gpio_in_sync1 <= 8'b0;
            gpio_in_sync2 <= 8'b0;
        end else begin
            gpio_in_sync1 <= gpio_in;
            gpio_in_sync2 <= gpio_in_sync1;
        end
    end

    always @(posedge clk) begin
        uart_tx_send <= 1'b0;
        uart_rx_ack <= 1'b0;
        if (reset) begin
            cycle_count <= 32'b0;
            mmio_rdata <= 32'b0;
            uart_tx_data <= 8'b0;
            gpio_out <= 8'b0;
        end else begin
            cycle_count <= cycle_count + 1'b1;
            if (mmio_sel) begin
                case (mem0_addr[7:2])
                    6'd0: begin
                        if (mem0_wstrb[0]) begin
                            uart_tx_data <= mem0_wdata[7:0];
                            uart_tx_send <= 1'b1;
                        end
                    end
                    6'd1: mmio_rdata <= {31'b0, uart_tx_ready};
                    6'd2: begin
                        mmio_rdata <= {24'b0, uart_rx_data};
                        uart_rx_ack <= 1'b1;
                    end
                    6'd3: mmio_rdata <= {31'b0, uart_rx_ready};
                    6'd4: mmio_rdata <= cycle_count;
                    6'd5: mmio_rdata <= {24'b0, gpio_in_sync2};
                    6'd6: begin
                        if (mem0_wstrb[0]) begin
                            gpio_out <= mem0_wdata[7:0];
                        end
                    end
                    default: mmio_rdata <= 32'b0;
                endcase
            end
        end
    end

    wire lms_hit;
    wire [31:0] lms_rdata;
    /* Task RAM stream ports (UART bridge <-> LMS bridge pass-through, SHAKE256 path, 12-bit task RAM address) */
    wire        stream_wr_en;
    wire [11:0] stream_wr_addr;
    wire [31:0] stream_wr_data;
    wire        stream_rd_en;
    wire [11:0] stream_rd_addr;
    wire        stream_rd_valid;
    wire [31:0] stream_rd_data;
    wire        stream_busy;

    lms_sha256_mmio_bridge #(
        .LMS_BASE(LMS_BASE),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .ENABLE_SHA256(ENABLE_SHA256),
        .ENABLE_SHAKE256(ENABLE_SHAKE256),
        .HAS_SECURITY(HAS_SECURITY),
        .RANDOM_DELAY(RANDOM_DELAY),
        .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE)
    ) lms_bridge (
        .clk(clk),
        .rst(reset),
        .mem_valid(lms_bus_valid),
        .mem_addr(lms_bus_addr),
        .mem_wdata(lms_bus_wdata),
        .mem_wstrb(lms_bus_wstrb),
        .mem_hit(lms_hit),
        .mem_ready(),
        .mem_rdata(lms_rdata),
        .stream_wr_en(stream_wr_en),
        .stream_wr_addr(stream_wr_addr),
        .stream_wr_data(stream_wr_data),
        .stream_rd_en(stream_rd_en),
        .stream_rd_addr(stream_rd_addr),
        .stream_rd_valid(stream_rd_valid),
        .stream_rd_data(stream_rd_data),
        .stream_busy(stream_busy)
    );

    /* TRNG independent MMIO peripheral (C1, address region 0x1700_0000). */
    wire trng_hit;
    wire [31:0] trng_rdata;
    lms_trng_mmio #(
        .TRNG_BASE(TRNG_BASE),
        .SIM_MODE(TRNG_SIM_MODE)
    ) trng_periph (
        .clk(clk),
        .rst(reset),
        .mem_valid(!reset && mem0_valid),
        .mem_addr(mem0_addr),
        .mem_wdata(mem0_wdata),
        .mem_wstrb(mem0_wstrb),
        .mem_hit(trng_hit),
        .mem_ready(),
        .mem_rdata(trng_rdata)
    );

    /* UART<->task RAM pass-through bridge (Step 3, address region 0x1800_0000). */
    wire bridge_hit;
    wire [31:0] bridge_rdata;    lms_uart_bridge #(
        .BRIDGE_BASE(BRIDGE_BASE)
    ) uart_bridge (
        .clk(clk),
        .rst(reset),
        .mem_valid(!reset && mem0_valid &&
                   mem0_addr[31:10] == BRIDGE_BASE[31:10]),
        .mem_write(ibex_data_we),
        .mem_addr(mem0_addr),
        .mem_wdata(mem0_wdata),
        .mem_wstrb(mem0_wstrb),
        .mem_hit(bridge_hit),
        .mem_rdata(bridge_rdata),
        .rx_data(uart_rx_data),
        .rx_rdy(uart_rx_ready),
        .rx_ack(bridge_rx_ack),
        .tx_data(bridge_tx_data),
        .tx_send(bridge_tx_send),
        .tx_ready(uart_tx_ready),
        .stream_wr_en(stream_wr_en),
        .stream_wr_addr(stream_wr_addr),
        .stream_wr_data(stream_wr_data),
        .stream_rd_en(stream_rd_en),
        .stream_rd_addr(stream_rd_addr),
        .stream_rd_valid(stream_rd_valid),
        .stream_rd_data(stream_rd_data),
        .stream_busy(stream_busy),
        .busy(bridge_busy)
    );

    /* SPI flash peripheral (M1 access verification, address region 0x1900_0000). */
    wire flash_hit;
    wire [31:0] flash_rdata;
    lms_flash_spi #(
        .FLASH_BASE(FLASH_BASE)
    ) flash_periph (
        .clk(clk),
        .rst(reset),
        .mem_valid(!reset && mem0_valid),
        .mem_addr(mem0_addr),
        .mem_wdata(mem0_wdata),
        .mem_wstrb(mem0_wstrb),
        .mem_hit(flash_hit),
        .mem_ready(),
        .mem_rdata(flash_rdata),
        .spi_sck(spi_sck),
        .spi_sck_en(spi_sck_en),
        .spi_cs_n(spi_cs_n),
        .spi_mosi(spi_mosi),
        .spi_miso(spi_miso)
    );

    reg [31:0] lms_rdata_q;
    reg [31:0] trng_rdata_q;
    reg [31:0] bridge_rdata_q;
    reg [31:0] flash_rdata_q;

    assign mem0_rdata = rdata_source == RDATA_RAM ? ram_rdata :
                        rdata_source == RDATA_MMIO ? mmio_rdata :
                        rdata_source == RDATA_LMS ? lms_rdata_q :
                        rdata_source == RDATA_TRNG ? trng_rdata_q :
                        rdata_source == RDATA_BRIDGE ? bridge_rdata_q :
                        rdata_source == RDATA_FLASH ? flash_rdata_q :
                        32'hdead_beef;

    reg [2:0] rdata_source;
    always @(posedge clk) begin
        if (reset) begin
            rdata_source <= RDATA_NONE;
            data_rvalid <= 1'b0;
            lms_rdata_q <= 32'b0;
            trng_rdata_q <= 32'b0;
            bridge_rdata_q <= 32'b0;
            lms_bus_valid <= 1'b0;
            lms_bus_read <= 1'b0;
            lms_bus_read_wait <= 1'b0;
            lms_bus_addr <= 32'b0;
            lms_bus_wdata <= 32'b0;
            lms_bus_wstrb <= 4'b0;
            ram_req_pending <= 1'b0;
            ram_addr_q <= {RAM_WORD_XADR{1'b0}};
            ram_wdata_q <= 32'b0;
            ram_wen_q <= 4'b0;
        end else begin
            data_rvalid <= (mem0_valid && !lms_req && !ram_sel) || ram_req_pending ||
                           (lms_bus_valid && (!lms_bus_read || lms_bus_read_wait));
            rdata_source <= (lms_bus_valid && (!lms_bus_read || lms_bus_read_wait)) ? RDATA_LMS :
                            ram_req_pending  ? RDATA_RAM :
                            mmio_sel         ? RDATA_MMIO :
                            trng_hit         ? RDATA_TRNG :
                            bridge_hit       ? RDATA_BRIDGE :
                            flash_hit        ? RDATA_FLASH : RDATA_NONE;

            ram_req_pending <= ram_sel;
            ram_wen_q <= 4'b0;
            if (ram_sel) begin
                ram_addr_q <= mem0_addr[`LMS_SOC_RAM_XADR-1:2];
                ram_wdata_q <= mem0_wdata;
                ram_wen_q <= mem0_wstrb;
            end

            if (!lms_bus_valid && lms_req) begin
                lms_bus_valid <= 1'b1;
                lms_bus_read <= !ibex_data_we;
                lms_bus_read_wait <= 1'b0;
                lms_bus_addr <= mem0_addr;
                lms_bus_wdata <= mem0_wdata;
                lms_bus_wstrb <= mem0_wstrb;
            end else if (lms_bus_valid && lms_bus_read && !lms_bus_read_wait) begin
                lms_bus_read_wait <= 1'b1;
            end else if (lms_bus_valid) begin
                lms_bus_valid <= 1'b0;
                lms_bus_read_wait <= 1'b0;
            end

            if (lms_hit) begin
                lms_rdata_q <= lms_rdata;
            end
            if (trng_hit) begin
                trng_rdata_q <= trng_rdata;
            end
            if (bridge_hit) begin
                bridge_rdata_q <= bridge_rdata;
            end
            if (flash_hit) begin
                flash_rdata_q <= flash_rdata;
            end
        end
    end

endmodule

`default_nettype wire
