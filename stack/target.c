#include<stdio.h>
#include <stdlib.h>

void hello(){
    printf("hello stack!\n");
    exit(0);
}


int my_get(int n, char* dest){
    while(n-- > 0){
        *dest = getc(stdin);
        dest++;
    }
}


void work(){
    
    char a[8] = {'x'};
    int length;
    scanf("%d", &length);
    my_get(length, a);
}

int main(){
    printf("begin normally\n");
    work();
    printf("end normally\n");
    return 0;
}