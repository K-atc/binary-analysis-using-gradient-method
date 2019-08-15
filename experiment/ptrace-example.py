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
    # print("memory mapping = {}".format(mmap))
    for x in mmap:
        if x.pathname and '/sample/' in str(x.pathname):
            text_base_addr = x.start
            print("{:#x} {}".format(x.start, x.pathname))
            break

    print("Add breakpoint")
    bp0 = process.createBreakpoint(text_base_addr + 0x7d2) # cmp inst
    bp1 = process.createBreakpoint(text_base_addr + 0x7d6) # cmp inst
    print("breakpoints = {:#x}, {:#x}".format(bp0.address, bp1.address))

    print("cont()")
    process.cont()

    print("wait signal")
    process.waitSignals(signal.SIGINT, signal.SIGTRAP)

    print("hit breakpoint")
    print("pc = {:#x}".format(process.getInstrPointer()))
    # process.removeBreakpoint(bp0) # optional
    print("print registers")
    regs = process.getregs()
    print("rax = {:#x}".format(regs.rax))
    print("al = {:#x}".format(process.getreg('al')))
    x_0 = process.getreg('al')

    print("cont()")
    process.cont()

    print("wait signal")
    process.waitSignals(signal.SIGINT, signal.SIGTRAP, signal.SIGSEGV)

    print("hit breakpoint")
    # process.removeBreakpoint(bp1) # optional
    print("pc = {:#x}".format(process.getInstrPointer()))
    regs = process.getregs()
    x_len = struct.unpack('<I', process.readBytes(regs.rbp - 0xc, 4))[0]

    print("py: {}".format(json.dumps({'x_0': x_0, 'x_len': x_len})))

    process.detach()
    debugger.quit()

def main():
    args = ["sample/simple-if-statement-tree", "#aab"]
    tracee = subprocess.Popen(args)
    debugger_example(tracee.pid)
    tracee.kill()
    tracee.wait()

if __name__ == "__main__":
    main()