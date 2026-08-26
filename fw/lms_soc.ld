OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    ram (rwx) : ORIGIN = 0x00000080, LENGTH = 128K - 0x80
}

__stack_size = 32K;
__stack_top = ORIGIN(ram) + LENGTH(ram);

SECTIONS
{
    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    } > ram

    .rodata : {
        *(.rodata .rodata.*)
    } > ram

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > ram

    .bss (NOLOAD) : ALIGN(4) {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > ram

    __image_end = .;
    ASSERT(__image_end <= __stack_top - __stack_size,
           "firmware image overlaps reserved stack")
}
