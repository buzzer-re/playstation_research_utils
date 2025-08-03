.intel_syntax noprefix
.global memcpy

memcpy:
    push rdi
    push rsi
    push rcx

    mov rax, rdi      
    mov rcx, rdx     

    rep movsb        

    pop rcx
    pop rsi
    pop rdi
    ret
