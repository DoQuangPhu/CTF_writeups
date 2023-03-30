# BUFFER OVERFLOW + SHELL CODE
Tải chương trình về va kiểm tra các chế độ bảo vệ :

![image](https://user-images.githubusercontent.com/93699926/228743243-bd816515-c6a8-40b0-bb05-58f0ede79b30.png)

Phân tích code asm trong chương trình :

![image](https://user-images.githubusercontent.com/93699926/228743473-3317b633-4305-4f15-9f7c-d7d2b748c8f0.png)

Ta có thể thấy rằng từ start<0> -> start<+34> chương trình thiết lập các thanh ghi và push string "let start CTF:" vô stack và sau đó gọi syswrite(eax=0x4) và in dòng string đó ra cho mình

Từ start<+49> trở đi chương trình tiếp tục gọi hàm sysread cho phép chúng ta nhập vô tới 0x3c ký tự ,đọc xong thì chuong trình add esp thêm 0x14 và return .Đây rõ ràng là lỗi buffer overflow

Vì tất cả các chế độ bảo vệ đều bị tắt nên ta sẽ khai thác chương trình theo hướng đó là overwrite saved eip của chương trình và thức thi shellcode .Nhưng để có thể thực thi shellcode ta cần một con trỏ chỉ đến địa chỉ chứa shellcode của ta để có thực thi nó.

Vi vậy trước tiên ta cần leak địa chỉ stack .chạy chương trình và đặt break point ngay tại câu lệnh ret đê quan sát:

![image](https://user-images.githubusercontent.com/93699926/228746189-5e78761a-1b4e-40ba-8c73-6361fbdbf65a.png)

Ta có thể thấy ngay dưới esp stack đang chứa một con trỏ <0xffffd300> địa chỉ này chỉ ngay tới địa chỉ stack ngay dưới nó nếu ta lợi dụng lỗi bufferoverflow và ghi đè địa chỉ của saved eip quay trở lại địa chỉ start<+39>: để thực hiện syswrite thi chương trình sẽ in ra một mớ những gì trên stack và sau đó tiếp tục cho chúng ta một lần ghi nữa khi ngay bên dưới là các câu lệnh để thực thi sysread

![image](https://user-images.githubusercontent.com/93699926/228747600-875935d7-83d8-4928-a574-7a99a4c16c74.png)

GOOD! Bây giờ chúng ta đã leak đuọc địa chỉ của một con trỏ chỏ tới địa chỉ stack.Vậy ở lần ghi thứ 2 ta cần phải overwrite địa chi saved eip thành con trỏ ,cái mà trỏ tới đại chỉ stack chứa shell code của chúng ta 

BÂy giờ thi viết shell code để thực thi syscall execve
```
shellcode=asm(
    '''
    push 0x00000000
    push 0x68732F2F
    push 0x6E69622F  
    xor eax,eax
    xor ebx,ebx
    xor ecx,ecx
    xor edx,edx
    mov eax,0xb
    mov ebx,esp
    int 0x80
    '''
    )
 ```
 
 Đầu tiên ta push strng /bin//sh\x00 lên stack . Sau đó chỉ cần mov ebx,esp là ebx của chúng ta sẽ chỉ đến string "/bin//sh\x00", sau đó thiết lập các thanh ghi eax,ecx,edx tương ứng để thực thi syscall execve
 
 Vậy bây giờ ta chỉ cần overwrite địa chỉ eip ở lần ghi thứ 2 với địa chỉ stack leak được ở lần ghi 1 . Tính toán sao cho địa chỉ đó chỉ tới địa chỉ chứa shell code của ta trên stack là được 
 
 Vì shellcode của chúng ta dài đến 27bytes nên ta payload 2 của chúng ta sẽ là 20bytes rác để padding đến địa chỉ saved eip , sau đó là địa chỉ  stack (tính toán sao cho nó chỉ tới địa chỉ chứa shellcode của ta ) và shellcode để lấy shell
 
 chạy chương trình và kiểm tra stack ngay trước lần nhập thứ 2 của ta 
 
 ![image](https://user-images.githubusercontent.com/93699926/228751877-4652b384-6532-4f05-9536-81fb9bbee71b.png)

Ta có thể thấy địa chỉ leak ra được là 0xffcdfd90 và ở lần nhập thứ 2 ta sẽ ghi lên địa chỉ stack bắt đầu 0xffcdfd8c ,Vì <0xffcdfd90> là địa chỉ <esp+4> nên sau khi ta nhập payload2 ta cần ghi đè saved eip eip thành < 0xffcdfd90+20> là địa chỉ chứa shellcode của ta

![image](https://user-images.githubusercontent.com/93699926/228753014-4339aee3-cdd4-423e-8a0d-72e26fa63325.png)

Chạy chương trình và ta lấy được shell:

![image](https://user-images.githubusercontent.com/93699926/228753528-abcd6ddc-d2bd-4202-8ca2-0c4df7cc4af9.png)

Chạy nó trên sever:

![image](https://user-images.githubusercontent.com/93699926/228755512-e1813380-0a2d-4700-b9e8-22fda6003917.png)
