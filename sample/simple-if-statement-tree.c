#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

void correct() {
    printf("correct.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: %s STRING\n", argv[0]);
        exit(1);
    }
    printf("[*] main = %p\n", main);

    char *x = argv[1];
    unsigned int x_len = strlen(x);
    printf("{\"%s\":%d,\"%s\":%d}\n", "x_0",x[0],  "x_len", x_len);
    if (x[0] == '#' && x_len == 3) {
        correct();
    }
}