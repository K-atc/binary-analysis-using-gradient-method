#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>

int main(int argc, char* argv[]) {

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_TRACEME, 0, NULL, NULL)");
    }

    char buf[1024];
    fgets(buf, sizeof(buf), stdin);
    printf("%s", buf);
}