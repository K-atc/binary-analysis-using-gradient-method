#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

void correct() {
    printf("correct.\n");
}

// __attribute__((constructor))
// void setup()
// {
//     printf("waiting for attach...\n");
//     sigset_t set;
//     int sig, res;
//     sigemptyset(&set); 
//     sigaddset(&set, SIGUSR1);
//     sigprocmask(SIG_BLOCK, &set, NULL);
//     res = sigwait(&set, &sig);
//     if (res != 0) handle_error_en(res, "sigwait");
//     if (sig == SIGUSR1) {
//         printf("Recieved SIGUSR1\n");
//     }
//     else {
//         printf("sig = %d\n", sig);
//     }
// }

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: %s STRING\n", argv[0]);
        exit(1);
    }
    char *x = argv[1];
    unsigned int x_len = strlen(x);
    printf("{\"%s\":%d,\"%s\":%d}\n", "x_0",x[0],  "x_len", x_len);
    if (x[0] == '#' && x_len == 3) {
        // asm volatile("int3");
        correct();
    }
}