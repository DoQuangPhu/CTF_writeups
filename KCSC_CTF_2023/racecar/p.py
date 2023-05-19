from pwn import* 
context.binary=exe=ELF('./racecar',checksec=False)
p=process(exe.path)


#for i in range(9):
p.sendlineafter(b"> ",b"1")
p.sendafter(b"Name for new racer: ",)

p.interactive()
