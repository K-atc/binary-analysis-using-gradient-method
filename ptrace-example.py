#!/usr/bin/python
import ptrace.debugger
import signal
import subprocess
import sys, os
import time

def debugger_example(pid):
    debugger = ptrace.debugger.PtraceDebugger()

    print("Attach the running process %s" % pid)
    process = debugger.addProcess(pid, False)

    mmap = process.readMappings()
    # print("memory mapping = {}".format(mmap))
    for x in mmap:
        if x.pathname and '/sample/' in str(x.pathname):
            text_base_addr = x.start
            print("{:#x} {}".format(x.start, x.pathname))
            break

    print("Add breakpoint")
    process.createBreakpoint(text_base_addr + 0xa76)

    time.sleep(1)

    print("cont()")
    process.cont()

    print("send signal")
    os.kill(pid, signal.SIGUSR1)

    print("wait signal")
    # process.waitSignals(signal.SIGTRAP)
    # process.cont()
    # process.waitSignals(signal.SIGINT, signal.SIGTRAP)
    process.waitSignals(signal.SIGUSR1)
    print("IP after: %#x" % process.getInstrPointer())
    
    print("send signal")
    os.kill(pid, signal.SIGUSR1)

    process.detach()
    debugger.quit()

def main():
    args = ["sample/simple-if-statement-tree2", "aaa"]
    tracee = subprocess.Popen(args)
    debugger_example(tracee.pid)
    tracee.kill()
    tracee.wait()

if __name__ == "__main__":
    main()