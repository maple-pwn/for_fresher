#include <stdio.h>

void shell(){
    system("/bin/sh");
}

void vulnerable(){
    char buf[12];
    puts("input 1:");
    read(0, buf, 100);
    puts(buf);
    puts("input 2:");
    fgets(buf, 0x100, stdin);
}

void main(){
    vulnerable();
}

