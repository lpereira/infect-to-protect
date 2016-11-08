;
; Stub for the infect-to-protect proof of concept
; Copyright (c) 2016 Leandro Pereira <leandro@tia.mat.br>
;

; Constants for BPF opcodes
bpf_ld	equ	0x00
bpf_w	equ	0x00
bpf_abs	equ	0x20
bpf_jmp	equ	0x05
bpf_jeq	equ	0x10
bpf_k	equ	0x00
bpf_ret	equ	0x06

seccomp_ret_errno	equ	0x00050000
seccomp_ret_allow	equ	0x7fff0000
seccomp_ret_trap	equ	0x00030000

audit_arch_x86_64	equ	(0x80000000|0x40000000|62)

%macro bpf_stmt 2 ; BPF statement
    dw (%1)
    db (0)
    db (0)
    dd (%2)
%endmacro

%macro bpf_jump 4 ; BPF jump
    dw (%1)
    db (%2)
    db (%3)
    dd (%4)
%endmacro

%macro sc_deny 2 ; Deny syscall
    bpf_jump {bpf_jmp+bpf_jeq+bpf_k}, 0, 1, %1
    bpf_stmt {bpf_ret+bpf_k}, {seccomp_ret_errno|%2}
%endmacro

%macro sc_allow 1 ; Allow syscall
    bpf_jump {bpf_jmp+bpf_jeq+bpf_k}, 0, 1, %1
    bpf_stmt {bpf_ret+bpf_k}, seccomp_ret_allow
%endmacro

section .text
    global _start

_start:
    ; Save registers that'll be clobbed
    push rax
    push rdi
    push rdx
    push rsi
    push rsp
    push r10
    push r8

    ; prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    mov     rax, 157  ; prctl
    mov     rdi, 38 ; PR_SET_NO_NEW_PRIVS
    mov     rsi, 1
    mov     rdx, 0
    mov     r10, 0
    mov     r8, 0
    syscall

    ; Too lazy to make this code relocatable, so use return address in the
    ; stack as a pointer to the struct sock_filter that the apply_filter
    ; routine will use.
    jmp filter

apply_filter:
    pop rdx

    ; Allocate & initialize a struct sock_fprog
    sub rsp, 16	; sizeof(struct sock_fprog)
    mov [rsp], word (bpf.end - bpf) / 8 ; unsigned short len
    mov [rsp + 8], qword rdx ; struct sock_filter *filter

    ; prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, tbl)
    mov     rax, 157 ; prctl
    mov     rdi, 22 ; PR_SET_SECCOMP
    mov     rsi, 2  ; SECCOMP_MODE_FILTER
    mov     rdx, rsp
    syscall

    ; Deallocate the sock_fprog
    add rsp, 16

    ; Restore clobbed registers
    pop r8
    pop r10
    pop rsp
    pop rsi
    pop rdx
    pop rdi
    pop rax

    ; 32-bit JMP placeholder to the original code (usually _start)
    db 0xe9
    dd 0x00000000

filter:
    call apply_filter

bpf:
    bpf_stmt {bpf_ld+bpf_w+bpf_abs}, 4
    bpf_jump {bpf_jmp+bpf_jeq+bpf_k}, 0, 1, audit_arch_x86_64
    bpf_stmt {bpf_ld+bpf_w+bpf_abs}, 0
    sc_allow 21
    sc_allow 158
    sc_allow 12
    sc_allow 3
    sc_allow 59
    sc_allow 231
    sc_allow 5
    sc_allow 9
    sc_allow 10
    sc_allow 11
    sc_allow 2
    sc_allow 0
    sc_allow 1
    bpf_stmt {bpf_ret+bpf_k},seccomp_ret_trap
bpf.end:
