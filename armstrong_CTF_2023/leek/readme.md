# heap overflow

kiểm tra các chế độ bảo vệ cơ bản của chương trình ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/234224634-6f6fcd8a-5cc2-40a7-af14-cecaa71ad847.png)

kiểm tra luồng thực thi của chương trình trong IDA ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/234224815-6911f752-0ad4-4fbd-9e2d-6f4cb99ea2a4.png)

![image](https://user-images.githubusercontent.com/93699926/234224892-ae3381c2-4cb0-416f-8647-c79efc0f413c.png)

chương trình đầu tiên sẽ gọi hàm random và gieo seed cho nó = time(0) nhìn vào vòng for loop ta thấy chương trình sẽ chạy 100 lần và mỗi lần chạy nó sẽ tạo ra malloc 2 lần 
lần 1 malloc(0x10) ứng với con trỏ v9 , lần 2 là malloc(0x20) ứng với con trỏ s.
Sau đó nó sẽ tạo ra một chuỗi nhưng ksy tự ứng với giá trị random và lưu byte by byte vô biến s.
Tiếp đó chương trình cho ta nhập vô biến v9 với hàm input(v9). kiểm tra input() ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/234226224-d11b9aa3-1c41-4876-8576-986a2cca26f1.png)

hàm input tạo một mảng lên tới 1288 byte và cho ta nhập vô tưng đó byte (không có overflow ở hàm này ), nhưng sau đó nó lại gọi hàm memcpy() để copy hết các ký tự ta nhập vô v9 . Nhớ rằng v9 chỉ được malloc có 0x10. và hơn nữa khi hai chunks v9 và s sẽ ngay liền kề nhau vì chúng  được malloc một cách lần lượt trên heap
.kiểm tra điều đó qua GDB ,đặt break point ngay trước khi nhảy vô hàm input(b * 0x4015e5), và kiểm tra các chunk ở trên heap ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/234228744-de0909d6-1b92-4ff1-8e07-024de87dcf50.png)

phần được high light màu vàng là chunks v9 và ngay bên dứoi là chunk s sau cùng là top chunks.với bug heap overflow trong tay ta có thể ghi đè nội dung ở chunk s thành nộ dung mà ta muốn vậy thì đỡ phải đoán nữa
.Nhưng lưu ý khi overflow chunk s ta cần giữ nguyên phần metadata của chunk 9 là (0 và 0x31 ) để sau đó khi chương trình free(v9) và free(s) sẽ không gặp lỗi . ta có thể sửa lại chunk s ở lần nhập tiếp sau khi pass qua hàm strcmp() của chương trình (dòng 44 trong IDA ấy )
```python
from pwn import *
context.binary=exe=ELF("./leek",checksec=False)
#libc=ELF('./libc_32.so.6',checksec=False)
p=process(exe.path)
def GDB():
            gdb.attach(p,gdbscript=
                '''
                b*0x4015e5
                c
                ''')
            input()
GDB()

#p=remote("challs.actf.co", 31310)
for i in range(0x64):
    print('[+]time'+str(i))
    payload=b'A'*(0x40-1)
    p.sendline(payload)
    secret=b"A"*(0x20-1)
    p.sendline(secret)
    payload=b"A"*0x10+p64(0)+p64(0x31)
    p.sendline(payload)
p.interactive()
```
mỗi lần input thì chunk sẽ như sau :

![image](https://user-images.githubusercontent.com/93699926/234230457-150415c3-a4d7-4e90-b62d-5ee80d955aa7.png)

và sau khi dược nhập lần nữa vào v9 thì ta sẽ sửa lại chunk s thành như sau :

![image](https://user-images.githubusercontent.com/93699926/234230902-91a77216-44fa-4d4f-bf55-3365b0a82feb.png)

và cứ làm thế hết 100 lần loop thì chương trình sẽ gọi hàm win() và cho ta flag:

full script in p.py
chạy chương trình trên server ta có flag như sau :

![image](https://user-images.githubusercontent.com/93699926/234231725-c38d8a76-8121-4288-bc5c-4fa3e54e7464.png)
