/* Pre-include shim: points MBEDTLS_CONFIG_FILE at this project's trimmed config.
 * Avoids the quote-escaping failure of -DMBEDTLS_CONFIG_FILE=\"...\" under MSYS2_ARG_CONV_EXCL='*'
 * (MSYS no longer turns \" into ", so a backslash in the macro value breaks #include).
 * Usage: add -include bench/mbedtls_cfg_file.h when compiling (used by both the PC self-check and the RV32 firmware). */
#define MBEDTLS_CONFIG_FILE "bench/mbedtls_lms_config.h"
