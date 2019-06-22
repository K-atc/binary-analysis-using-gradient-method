import os
import time
from ptrace.binding import ptrace_traceme


def run_tracee(args):
    pid = os.fork()
    if pid: # Parent process
        return pid
    else:
        res = ptrace_traceme()
        # print("ptrace_traceme() = {}".format(res))
        try:
            os.execv(args[0], args)
        except OSError as e:
            print(e)
            exit(1)

args = ["sample/simple-elf-checker"]
pid = run_tracee(args)
print("child process = {}".format(pid))
time.sleep(200)