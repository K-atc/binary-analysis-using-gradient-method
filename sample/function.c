#include <stdio.h>
#include <stdlib.h>

typedef unsigned long int T;

T f(T x, T a, T b, T c) {
    return a * x * x + b * x + c;
}

int main(int argc, char *argv[]) {
    if (argc <= 4) {
        printf("usage: %s x\n", argv[0]);
        exit(1);
    }

    T x = atof(argv[1]);
    T a = atof(argv[2]);
    T b = atof(argv[3]);
    T c = atof(argv[4]);

    double y = f(x, a, b, c);
    printf("f(x) = %f\n", y);
}