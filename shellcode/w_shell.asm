bits 64

section .data
    msg db 'infected', 0
    len equ $ - msg        

section .text
    global _start          
_start:
    mov rax, 1            
    mov rdi, 1           
    lea rsi, [rel msg]          
    mov rdx, len          
    syscall               

    mov rax, 60          
    xor rdi, rdi         
    syscall              
