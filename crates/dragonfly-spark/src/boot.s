; Dragonfly Spark - Multiboot1/2 entry point with 64-bit transition
;
; This assembly provides:
; 1. Multiboot1 header (for iPXE compatibility)
; 2. Multiboot2 header (for GRUB2 compatibility)
; 3. Framebuffer request for graphics mode (MB2 only)
; 4. Entry point that:
;    a. Sets up identity-mapped page tables
;    b. Enables long mode (64-bit)
;    c. Jumps to 64-bit Rust code
;
; Bootloader magic values passed to us:
; - Multiboot1: EAX = 0x2BADB002
; - Multiboot2: EAX = 0x36d76289

bits 32

section .multiboot_header
; ============================================================================
; Multiboot 1 Header (for iPXE)
; Must be within first 8KB, 4-byte aligned
; Uses AOUT_KLUDGE (bit 16) to specify load addresses explicitly,
; which helps bootloaders that don't understand ELF64.
; Requests video mode (bit 2) for framebuffer graphics.
; ============================================================================
align 4
mb1_header_start:
    dd 0x1BADB002                ; magic
    dd 0x00010007                ; flags: align (0) + meminfo (1) + video (2) + address fields (16)
    dd -(0x1BADB002 + 0x00010007) ; checksum: magic + flags + checksum = 0
    ; Address fields (required when bit 16 is set)
    dd mb1_header_start          ; header_addr: address of this header
    dd 0x100000                  ; load_addr: load at 1MB (matches linker script)
    dd 0                         ; load_end_addr: 0 = load entire file
    dd 0                         ; bss_end_addr: 0 = no BSS specification
    dd _entry                    ; entry_addr: jump to _entry (32-bit protected mode)
    ; Video mode fields (required when bit 2 is set)
    dd 0                         ; mode_type: 0 = linear graphics mode
    dd 1024                      ; width: 1024 pixels
    dd 768                       ; height: 768 pixels
    dd 32                        ; depth: 32 bits per pixel
mb1_header_end:

; ============================================================================
; Multiboot 2 Header (for GRUB2)
; Must be within first 32KB, 8-byte aligned
; ============================================================================
align 8
mb2_header_start:
    ; Multiboot2 magic number
    dd 0xe85250d6                ; magic
    dd 0                         ; architecture: i386 protected mode
    dd mb2_header_end - mb2_header_start ; header length
    dd 0x100000000 - (0xe85250d6 + 0 + (mb2_header_end - mb2_header_start)) ; checksum

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
mb2_header_end:

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
    resb 524288  ; 512 KiB stack (very large for smoltcp + network stack)
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

; GDT for real mode transition is built at runtime in low memory
; (see _entry code)

section .text
global _entry
global stack_bottom
global stack_top
extern _start

; ============================================================================
; Fixed low-memory addresses for real mode (must be < 64KB)
; ============================================================================
VBE_MODE_INFO_ADDR equ 0x2000   ; 256 bytes for VBE mode info
VBE_STATUS_ADDR    equ 0x2100   ; 4 bytes for VBE result
GDT_RM_ADDR        equ 0x2200   ; GDT for real mode transition
REAL_CODE_ADDR     equ 0x3000   ; Real mode code location
PM32_RETURN_ADDR   equ 0x4000   ; 32-bit return code location
RETURN_TARGET_ADDR equ 0x2104   ; Address to jump to after VBE (stored here)
SAVED_EDI_ADDR     equ 0x2108   ; Saved multiboot magic
SAVED_ESI_ADDR     equ 0x210C   ; Saved multiboot info pointer

_entry:
    ; Save multiboot info (EAX = magic, EBX = info pointer)
    mov edi, eax    ; Will be first arg to _start (via RDI in 64-bit)
    mov esi, ebx    ; Will be second arg to _start (via RSI in 64-bit)

    ; Save multiboot info to low memory (needed by vbe_setup_done for restore)
    mov [SAVED_EDI_ADDR], edi
    mov [SAVED_ESI_ADDR], esi

    ; ========================================================================
    ; Check if booted via Multiboot2 (GRUB) — if so, skip VBE BIOS setup.
    ; On UEFI systems there is NO BIOS, so INT 10h VBE calls would crash.
    ; GRUB already provides the framebuffer via the MB2 info structure.
    ; ========================================================================
    cmp eax, 0x36d76289     ; Multiboot2 magic?
    je vbe_setup_done       ; Skip VBE — GRUB already set up framebuffer

    ; ========================================================================
    ; VBE Setup - Drop to real mode, set graphics mode, return to protected
    ; Only runs on Multiboot1 (iPXE BIOS) where we have a real BIOS.
    ; At this point: 32-bit protected mode, paging disabled, A20 enabled
    ; ========================================================================

    ; Output 'V' to serial for debug
    mov dx, 0x3F8
    mov al, 'V'
    out dx, al

    ; Build GDT in low memory at GDT_RM_ADDR
    ; Entry 0: null
    mov dword [GDT_RM_ADDR + 0], 0
    mov dword [GDT_RM_ADDR + 4], 0
    ; Entry 1 (0x08): 16-bit code segment
    mov dword [GDT_RM_ADDR + 8], 0x0000FFFF
    mov dword [GDT_RM_ADDR + 12], 0x00009A00
    ; Entry 2 (0x10): 16-bit data segment
    mov dword [GDT_RM_ADDR + 16], 0x0000FFFF
    mov dword [GDT_RM_ADDR + 20], 0x00009200
    ; Entry 3 (0x18): 32-bit code segment
    mov dword [GDT_RM_ADDR + 24], 0x0000FFFF
    mov dword [GDT_RM_ADDR + 28], 0x00CF9A00
    ; Entry 4 (0x20): 32-bit data segment
    mov dword [GDT_RM_ADDR + 32], 0x0000FFFF
    mov dword [GDT_RM_ADDR + 36], 0x00CF9200
    ; GDT pointer (at GDT_RM_ADDR + 40)
    mov word [GDT_RM_ADDR + 40], 39        ; limit (5 entries * 8 - 1)
    mov dword [GDT_RM_ADDR + 42], GDT_RM_ADDR  ; base

    ; Build real mode IDT pointer (at GDT_RM_ADDR + 48)
    mov word [GDT_RM_ADDR + 48], 0x03FF    ; limit
    mov dword [GDT_RM_ADDR + 50], 0        ; base

    ; Copy real mode code to REAL_CODE_ADDR
    mov esi, real_mode_code_start
    mov edi, REAL_CODE_ADDR
    mov ecx, real_mode_code_end - real_mode_code_start
    rep movsb

    ; Copy 32-bit return code to PM32_RETURN_ADDR
    mov esi, pm32_return_code_start
    mov edi, PM32_RETURN_ADDR
    mov ecx, pm32_return_code_end - pm32_return_code_start
    rep movsb

    ; Clear VBE status
    mov dword [VBE_STATUS_ADDR], 0

    ; Store return target address (absolute address of vbe_setup_done)
    mov dword [RETURN_TARGET_ADDR], vbe_setup_done

    ; Load our GDT
    lgdt [GDT_RM_ADDR + 40]

    ; Load real mode IDT (BIOS IVT)
    lidt [GDT_RM_ADDR + 48]

    ; Load 16-bit data segments
    mov ax, 0x10            ; 16-bit data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7000

    ; Far jump to 16-bit protected mode code (now at REAL_CODE_ADDR)
    jmp 0x08:REAL_CODE_ADDR

; ============================================================================
; Real mode code template (copied to low memory at REAL_CODE_ADDR = 0x3000)
; All addresses are computed relative to REAL_CODE_ADDR
; ============================================================================
real_mode_code_start:
bits 16
    ; Output 'B' for 16-bit mode
    mov dx, 0x3F8
    mov al, 'B'
    out dx, al

    ; Clear PE bit to enter real mode
    mov eax, cr0
    and al, 0xFE
    mov cr0, eax

    ; Far jump to flush prefetch - use absolute address
    ; The code is copied to REAL_CODE_ADDR (0x3000), so real_entry offset is:
    ; REAL_CODE_ADDR + (real_entry_offset - real_mode_code_start)
    ; real_entry_offset is 17 bytes from start (after far jmp instruction)
    db 0xEA                 ; far jmp opcode
    dw REAL_CODE_ADDR + 17  ; offset: 0x3000 + 17 = 0x3011
    dw 0x0000               ; segment
; real_entry: (offset 17 from start)
    ; Set up real mode segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x7000

    ; Output 'E' for real mode
    mov dx, 0x3F8
    mov al, 'E'
    out dx, al

    ; Get VBE mode info
    mov ax, 0x4F01
    mov cx, 0x0118          ; Mode 0x118 (1024x768)
    mov di, VBE_MODE_INFO_ADDR
    int 0x10

    ; Set VBE mode with linear framebuffer
    mov ax, 0x4F02
    mov bx, 0x4118          ; Mode | LFB flag
    int 0x10
    mov [VBE_STATUS_ADDR], ax

    ; Output 'S' for set mode done
    mov dx, 0x3F8
    mov al, 'S'
    out dx, al

    ; Return to protected mode
    cli
    lgdt [GDT_RM_ADDR + 40]

    mov eax, cr0
    or al, 1
    mov cr0, eax

    ; Far jump to 32-bit code
    db 0x66, 0xEA           ; 32-bit far jmp
    dd PM32_RETURN_ADDR     ; offset
    dw 0x18                 ; 32-bit code segment selector
real_mode_code_end:
bits 32

; ============================================================================
; 32-bit return code template (copied to low memory)
; ============================================================================
pm32_return_code_start:
    ; Output 'R' for return
    mov dx, 0x3F8
    mov al, 'R'
    out dx, al

    ; Load 32-bit data segments
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Jump back to main code via indirect jump (address stored at RETURN_TARGET_ADDR)
    jmp dword [RETURN_TARGET_ADDR]
pm32_return_code_end:

vbe_setup_done:
    ; ========================================================================
    ; Continue with normal boot - page tables and long mode
    ; Restore EDI/ESI (multiboot info) that was clobbered during VBE setup
    ; ========================================================================
    mov edi, [SAVED_EDI_ADDR]
    mov esi, [SAVED_ESI_ADDR]

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

    ; Enable SSE (required for x86_64 ABI)
    ; Step 1: Clear CR0.EM (bit 2) and set CR0.MP (bit 1)
    mov rax, cr0
    and ax, 0xFFFB      ; Clear EM (bit 2)
    or ax, 0x0002       ; Set MP (bit 1)
    mov cr0, rax

    ; Step 2: Set CR4.OSFXSR (bit 9) and CR4.OSXMMEXCPT (bit 10)
    mov rax, cr4
    or ax, (1 << 9) | (1 << 10)  ; OSFXSR | OSXMMEXCPT
    mov cr4, rax

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
