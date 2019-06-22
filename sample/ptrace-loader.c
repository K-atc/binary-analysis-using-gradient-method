#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("usage: %s TRACEE [TRACEE_ARGS ...]\n", argv[0]);
        exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("failed to fork");
    }
    else if (pid == 0) {
        //子プロセス処理
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("failed to traceme");
        }

        printf("argv[0] = %s\n", argv[1]);
        execve(argv[1], &argv[1], NULL);
        _exit(0); //子プロセスでは終了時には_exitを呼ぶことに注意!
    }
    else {
        //親プロセス処理
        printf("attach to %d\n", pid);

        long ret;

        ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        if (ret < 0) {
            perror("failed to attach");
            exit(1);
        }
        printf("attached to %d (ret: %ld)\n", pid, ret);

        ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
        if (ret < 0) {
            perror("failed to detach");
            exit(1);
        }
        printf("detached from %d (ret: %ld)\n", pid, ret);

        exit(0); //親プロセスでは終了時にはexitを呼ぶ
    }
}