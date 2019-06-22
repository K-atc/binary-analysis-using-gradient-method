#!/usr/bin/python
import ptrace.debugger
from ptrace.func_call import FunctionCallOptions
from ptrace.debugger.child import createChild
from ptrace.binding import ptrace_traceme, ptrace_syscall
import signal
import subprocess
import sys, os
import time
import struct
import json
import ctypes

def debugger_example(pid):
    debugger = ptrace.debugger.PtraceDebugger()

    print("Attach the running process %s" % pid)
    process = debugger.addProcess(pid, False)

    print("syscall()")
    # ptrace_syscall(pid)

    # syscall_options = FunctionCallOptions(
    #         write_types=True,
    #         write_argname=True,
    #         string_max_length=300,
    #         replace_socketcall=False,
    #         write_address=True,
    #         max_array_count=20,
    #     )
    # state = process.syscall_state
    # syscall = state.event(syscall_options)
    # if syscall and (syscall.result is not None):
    #     self.displaySyscall(syscall)

    for i in range(5):
        # Break at next syscall
        # process.syscall()
        # event = process.waitSyscall()
        event = debugger.waitProcessEvent()
        # event = process.waitSignals()
        # event = process.waitSignals(signal.SIGTRAP)
        print(event)
        regs = process.getregs()
        print("rax = {}".format(ctypes.c_long(regs.rax).value))
        print("rdi = {:#x}".format(regs.rdi))
        print("rsi = {:#x}".format(regs.rsi))
        print("rdx = {:#x}".format(regs.rdx))

        process.cont()

    ip = process.getInstrPointer()
    print("ip = {:#x}".format(ip))

    # res = process.getregs()
    # print(regs)

    print("detach()")
    process.detach()
    debugger.quit()

    print("="*8)

def run_tracee(args):
    pid = os.fork()
    if pid: # Parent process
        return pid
    else:
        time.sleep(1)
        print("spawn child process...")
        # res = ptrace_traceme()
        # print("ptrace_traceme() = {}".format(res))
        try:
            os.execv(args[0], args)
        except OSError as e:
            print(e)
            exit(1)

def main():
    args = ["sample/simple-elf-checker"]
    # tracee_pid = createChild(args, False)
    tracee_pid = run_tracee(args)
    # tracee_pid = subprocess.Popen(args, stdin=open('/bin/sh')).pid
    # tracee_pid = subprocess.Popen(args).pid

    with open('/proc/{}/cmdline'.format(tracee_pid)) as f:
        print(f.read())

    try:
        os.kill(tracee_pid, 0)
    except OSError as err:
        print(err)
        exit()

    # print(sys.argv)
    # tracee_pid = int(sys.argv[1])

    # os.system("strace -p {}".format(tracee_pid))

    debugger_example(tracee_pid)
    # os.kill(tracee_pid, signal.SIGTERM)

if __name__ == "__main__":
    main()