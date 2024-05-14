#include<stdio.h>
#include<stdlib.h>


int main(int argc, char **argv) {
  unsigned long buf[2];
  printf("main=%p / system=%p\n", main, system);
  for (int i = 0; i < 8; i++)
    printf("+%02xh: %016lx\n", i*8, buf[i]);
  return 0;
}