; Dragonfly Spark - Multiboot2 entry point
;
; This assembly provides:
; 1. Multiboot2 header (required for bootloader recognition)
; 2. Framebuffer request for 1024x768 graphics mode
; 3. Entry point that sets up stack and calls Rust code

section .multiboot_header
align 8
header_start:
    ; Multiboot2 magic number
    dd 0xe85250d6                ; magic
    dd 0                         ; architecture: i386 protected mode
    dd header_end - header_start ; header length
    dd 0x100000000 - (0xe85250d6 + 0 + (header_end - header_start)) ; checksum

    ; Framebuffer tag - request best available resolution at 32bpp
    ; Setting width/height to 0 means "use best available"
    align 8
    dw 5    ; type: framebuffer tag
    dw 0    ; flags: optional
    dd 20   ; size of this tag
    dd 0    ; width: 0 = best available
    dd 0    ; height: 0 = best available
    dd 32   ; depth: 32 bits per pixel

    ; End tag
    align 8
    dw 0    ; type
    dw 0    ; flags
    dd 8    ; size
header_end:

section .bss
align 16
stack_bottom:
    resb 16384  ; 16 KiB stack
stack_top:

section .text
global _entry
extern _start

_entry:
    ; Set up stack
    mov esp, stack_top

    ; Push multiboot info pointer and magic (for Rust _start)
    push ebx    ; multiboot info pointer
    push eax    ; multiboot magic number

    ; Call Rust entry point
    call _start

    ; Should never return, but if it does, halt
.hang:
    cli
    hlt
    jmp .hang
