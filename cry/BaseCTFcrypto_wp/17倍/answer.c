#include <stdio.h> 
#include <string.h>
int main(){
    unsigned char cipher[] = {
        98, 113, 163, 181, 115, 148, 166,  43,   9,  95,
        165, 146,  79, 115, 146, 233, 112, 180,  48,  79,
        65, 181, 113, 146,  46, 249,  78, 183,  79, 133,
        180, 113, 146, 148, 163,  79,  78,  48, 231,  77
    };
    for(int i=0;i<40;i++){
        for(int j=31;j<127;j++){
            int temp=(j*17)%256;
            if(temp==cipher[i]){
                printf("%c",j);
                break;
            }
        }
    }
    return 0;
}