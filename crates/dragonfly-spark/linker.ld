/* Dragonfly Spark linker script */

ENTRY(_entry)

SECTIONS {
    /* Start at 1 MiB - standard location for multiboot kernels */
    . = 1M;

    /* Multiboot header must be in first 32 KiB of file and 8-byte aligned */
    /* Place it at the very start */
    .multiboot_header : ALIGN(8) {
        KEEP(*(.multiboot_header))
    }

    /* Code section - start right after header to keep it in first 32KB */
    .text : ALIGN(16) {
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : ALIGN(16) {
        *(.data .data.*)
    }

    /* Uninitialized data (BSS) */
    .bss : ALIGN(16) {
        *(COMMON)
        *(.bss .bss.*)
    }

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note.*)
        *(.comment)
    }
}
