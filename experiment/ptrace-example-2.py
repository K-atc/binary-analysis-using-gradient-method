#!/usr/bin/python
import ptrace.debugger
import signal
import subprocess
import sys, os
import time
import struct
import json

def debugger_example(pid):
    debugger = ptrace.debugger.PtraceDebugger()

    print("Attach the running process %s" % pid)
    process = debugger.addProcess(pid, False)

    print("IP = {:#x}".format(process.getInstrPointer()))

    mmap = process.readMappings()
    for x in mmap:
        print(x)

def main():
    args = sys.argv[1:]
    tracee = subprocess.Popen(args)
    debugger_example(tracee.pid)
    tracee.kill()
    tracee.wait()

if __name__ == "__main__":
    main()