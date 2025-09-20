.intel_syntax noprefix
.global int_handler
.global ipi_int_handler
.extern handle_ipi_request
.extern handle_int
.extern justreturn

.macro SAVE_GP_REGISTERS
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rcx
    push rax
.endm

.macro RESTORE_GP_REGISTERS
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
.endm

.text


ipi_int_handler:
    SAVE_GP_REGISTERS
    mov rdi, rsp
    call handle_ipi_request
    RESTORE_GP_REGISTERS
    iretq

int_handler:
    SAVE_GP_REGISTERS
    mov rdi, rsp
    call handle_int
    RESTORE_GP_REGISTERS
    iretq