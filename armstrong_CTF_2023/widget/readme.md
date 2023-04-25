# RET2WIN

Kiểm tra các chế độ bảo vệ cơ bản của chương trình :

![image](https://user-images.githubusercontent.com/93699926/234171372-a6c52233-f5e5-4acb-8c19-0582600f2270.png)

Kiểm tra chương trình qua IDA ta có như sau :

![image](https://user-images.githubusercontent.com/93699926/234171580-3d213fe4-6c38-4038-ba16-5eed725b69b1.png)

ta cũng phát hiện chương trình có hàm win sẽ in flag ra cho ta như sau :

![image](https://user-images.githubusercontent.com/93699926/234171657-b4af11ea-0ecf-4920-a0d8-9fc18773070c.png)

ta phát hiện chương trình có lỗi format string 
đồng thời là lỗi buffer overflow khi nó sẽ hỏi chúng ta muốn nhập vô bao nhiêu ký tự và lưu vào biến v4 đồng thời chương trình sẽ đòng ngần đó ký tự vào biến buf đã được khai báo 24 byté trước đó

Ta sẽ lợi dung lỗi bof để ghi đè địa chỉ trả về của hàm main về thành hàm win nhưng ta thấy hàm win sẽ check 2 arg của hàm tương ứng với 2 lần check trước khi in flag ra cho ta .
Vậy nên thay vì nhảy vô hàm win ta sẽ nhảy vô <win +117> .Đây là code asm được dump ra từ hàm WIN():

![image](https://user-images.githubusercontent.com/93699926/234172331-34fca45a-bc5b-405e-8c75-482f352f11af.png)

![image](https://user-images.githubusercontent.com/93699926/234172405-ef49b377-7b3c-48f4-845e-301b25ae740d.png)

cụ thể hơn ta thấy sau khi gọi hàm fopen , thanh rax sẽ lưu fd (file descripter) của chúng ta và sau đó nó sẽ được lưu vô địa chỉ [rbp-0x8]
=>> Vậy để tránh xảy ra lỗi khi ta overflow saved rip của main ta cần ghi đè cả địa chỉ rbp của main thành địa chỉ hơp lệ có quyền RW :
 .Kiếm địa chỉ đó trong khi chạy chương trình ta được như sau :
  
  ![image](https://user-images.githubusercontent.com/93699926/234172808-d49e1f55-2f35-47f6-832a-cf494dacc1e6.png)

  khoảng địa chỉ in đậm là địa chỉ mà ta sẽ sử dụng để ghi đè rbp:
  
  ok script sẽ như sau :
  ```python
  arg1=0x402008
arg2=0x403029
rw_section=0x00000000404a00
payload=b"\x00"*(offset-8)+p64(rw_section)
payload+=p64(ret)+p64(ret)
payload+=p64(exe.sym['win']+117)

p.sendlineafter(b"Amount: ",b"100")
p.sendlineafter(b'Contents: ',payload)
  ```
 Ở bài này khi chạy trên sever ta thấy nó sẽ không thực thi chươnh trình ngay mà nó sẽ chạy cái này , mình đi hỏi thì đây là để tráng bruteforce hay gì đó . để chạy chương trình ta chỉ cần thêm đoạn code sau :
 ```python
p.recvuntil(b"proof of work: ")
foo = p.recvline().decode()
print(foo)
resultCapcha = subprocess.getoutput(foo)
print(resultCapcha)
p.sendline(resultCapcha)
 ```
! nếu chạy trên local các bạn bỏ phần code này đi là được
  
Full script in p.py
  
Chạy chương trình trên sever ta được flag :
  
![image](https://user-images.githubusercontent.com/93699926/234173332-001305ed-91c7-4e34-97f7-694f28f6a109.png)
