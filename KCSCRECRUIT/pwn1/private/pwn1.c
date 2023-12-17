#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include <sys/mman.h>

void timeout() {
    puts("Timeout");
    exit(1);
}

void setup() {
    signal(0xe,&timeout);
    alarm(60);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}


int main()
{
    setup();
    void *code = mmap(0x1337000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    puts("Let warm up a bit with shellcode , shall we?");
    read(0,code,12);
    puts("OK let see how your shellcode work!!!!");
    
    void (*func)(void) =  code;
    (*func)(); 
    return 0;
}