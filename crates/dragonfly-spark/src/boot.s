; Dragonfly Spark - Multiboot2 entry point with 64-bit transition
;
; This assembly provides:
; 1. Multiboot2 header (required for bootloader recognition)
; 2. Framebuffer request for graphics mode
; 3. Entry point that:
;    a. Sets up identity-mapped page tables
;    b. Enables long mode (64-bit)
;    c. Jumps to 64-bit Rust code

bits 32

section .multiboot_header
align 8
header_start:
    ; Multiboot2 magic number
    dd 0xe85250d6                ; magic
    dd 0                         ; architecture: i386 protected mode
    dd header_end - header_start ; header length
    dd 0x100000000 - (0xe85250d6 + 0 + (header_end - header_start)) ; checksum

    ; Framebuffer tag - request best available resolution at 32bpp
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
align 4096
; Page tables for identity mapping first 4GB (needed for framebuffer at ~0xFC000000)
p4_table:
    resb 4096
p3_table:
    resb 4096
p2_table_0:
    resb 4096   ; Maps 0GB-1GB
p2_table_1:
    resb 4096   ; Maps 1GB-2GB
p2_table_2:
    resb 4096   ; Maps 2GB-3GB
p2_table_3:
    resb 4096   ; Maps 3GB-4GB

align 16
stack_bottom:
    resb 131072  ; 128 KiB stack (large for deep call stacks)
stack_top:

section .rodata
gdt64:
    dq 0                                    ; null descriptor
.code: equ $ - gdt64
    dq (1<<43) | (1<<44) | (1<<47) | (1<<53) ; code segment: executable, code segment, present, 64-bit
.data: equ $ - gdt64
    dq (1<<44) | (1<<47)                    ; data segment: code segment=0 (data), present
.pointer:
    dw $ - gdt64 - 1                        ; limit (size - 1)
    dq gdt64                                ; base address

section .text
global _entry
extern _start

_entry:
    ; Save multiboot info (EAX = magic, EBX = info pointer)
    mov edi, eax    ; Will be first arg to _start (via RDI in 64-bit)
    mov esi, ebx    ; Will be second arg to _start (via RSI in 64-bit)

    ; Set up identity mapping page tables for 4GB
    ; P4[0] -> P3
    mov eax, p3_table
    or eax, 0b11    ; present + writable
    mov [p4_table], eax

    ; P3[0] -> P2_0 (0GB-1GB)
    mov eax, p2_table_0
    or eax, 0b11    ; present + writable
    mov [p3_table], eax

    ; P3[1] -> P2_1 (1GB-2GB)
    mov eax, p2_table_1
    or eax, 0b11
    mov [p3_table + 8], eax

    ; P3[2] -> P2_2 (2GB-3GB)
    mov eax, p2_table_2
    or eax, 0b11
    mov [p3_table + 16], eax

    ; P3[3] -> P2_3 (3GB-4GB)
    mov eax, p2_table_3
    or eax, 0b11
    mov [p3_table + 24], eax

    ; Map P2_0: 0..1GB using 2MB pages
    mov ecx, 0
.map_p2_0:
    mov eax, 0x200000   ; 2MB
    mul ecx
    or eax, 0b10000011  ; present + writable + huge page
    mov [p2_table_0 + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_p2_0

    ; Map P2_1: 1GB..2GB
    mov ecx, 0
.map_p2_1:
    mov eax, ecx
    add eax, 512        ; Offset by 512 (1GB / 2MB)
    mov edx, 0x200000
    mul edx
    or eax, 0b10000011
    mov [p2_table_1 + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_p2_1

    ; Map P2_2: 2GB..3GB
    mov ecx, 0
.map_p2_2:
    mov eax, ecx
    add eax, 1024       ; Offset by 1024 (2GB / 2MB)
    mov edx, 0x200000
    mul edx
    or eax, 0b10000011
    mov [p2_table_2 + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_p2_2

    ; Map P2_3: 3GB..4GB
    mov ecx, 0
.map_p2_3:
    mov eax, ecx
    add eax, 1536       ; Offset by 1536 (3GB / 2MB)
    mov edx, 0x200000
    mul edx
    or eax, 0b10000011
    mov [p2_table_3 + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_p2_3

    ; Load P4 table address into CR3
    mov eax, p4_table
    mov cr3, eax

    ; Enable PAE (Physical Address Extension)
    mov eax, cr4
    or eax, 1 << 5      ; PAE bit
    mov cr4, eax

    ; Enable long mode in EFER MSR
    mov ecx, 0xC0000080 ; EFER MSR
    rdmsr
    or eax, 1 << 8      ; LME (Long Mode Enable) bit
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, 1 << 31     ; PG (Paging) bit
    mov cr0, eax

    ; Load 64-bit GDT
    lgdt [gdt64.pointer]

    ; Far jump to 64-bit code
    jmp gdt64.code:long_mode_start

bits 64
long_mode_start:
    ; Clear all data segment registers
    xor ax, ax
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Set up 64-bit stack
    mov rsp, stack_top

    ; Arguments are already in EDI/ESI from 32-bit code
    ; Zero-extend to 64-bit
    mov eax, edi
    mov edi, eax        ; multiboot_magic in RDI
    mov eax, esi
    mov esi, eax        ; multiboot_info in RSI

    ; Call Rust entry point
    ; _start(multiboot_magic: u32, multiboot_info: u32) -> !
    call _start

    ; Should never return, but if it does, halt
.hang:
    cli
    hlt
    jmp .hang
