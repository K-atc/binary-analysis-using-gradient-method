import os
import signal
import subprocess
import struct
import time
import functools

import ptrace.debugger
import ptrace.error
from ptrace.debugger.process_event import ProcessEvent, NewProcessEvent, ProcessExit
from ptrace.debugger.process_error import ProcessError
import angr
import capstone
import psutil

from .ast import constraint as ir
from .exceptions import *
from .fs import FileSystem

### REFACTOR: rename var to var_name
def var(insn, op):
    addr = insn.address
    var_type = "undefined"
    value = "undefined"
    if op.type == capstone.x86.X86_OP_REG:
        var_type = "reg"
        value = "{}".format(insn.reg_name(op.reg))
    if op.type == capstone.x86.X86_OP_MEM:
        var_type = "mem"
        str_index_scale = ""
        if op.mem.index:
            str_index_scale = "+{}*{}".format(
                insn.reg_name(op.mem.index),
                op.mem.scale,
                )
        value = "{}{}{:+#x}".format(
            insn.reg_name(op.mem.base),
            str_index_scale,
            op.mem.disp,
            )
        value = value.replace('0x', '')
        value = value.replace('+', 'plus')
        value = value.replace('-', 'minus')
        value = value.replace('*', 'multiply')
    return "var_{:x}_{}_{:}".format(addr, var_type, value)

def bytes_to_uint(p, size):
    if size == 1: 
        return struct.unpack("<B", p)[0]
    if size == 2: 
        return struct.unpack("<H", p)[0]
    if size == 4: 
        return struct.unpack("<I", p)[0]
    if size == 8: 
        return struct.unpack("<Q", p)[0]
    raise UnhandledCaseError


def strip_null(s):
    first_null_pos = s.find('\x00')
    if first_null_pos >= 0:
        return s[:first_null_pos]
    else:
        return s

def vector_to_string(v):
    try:
        s = ''.join(map(lambda _: chr(_) if _ > 0 else '\x00', v.list()))
        return s
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, v))
        traceback.print_exc()
        print("-> v = {}".format(v))
        exit(1)

class FixedValue(int):
    def __repr__(self):
        return "FixedValue({})".format(self)

def close_dangling_files():
    p = psutil.Process()
    for f in p.open_files():
        # print(f)
        if f.path.startswith("/proc/") and f.path.endswith("/mem"):
            print("[!] close dangling file: {}".format(f))
            os.close(f.fd)

def get_addr_from_env(key):
    try:
        v = os.environ[key]
        return int(v, 16)
    except KeyError as e:
        print("[!] Environment variable {} is not set".format(key))
        raise e

def round_real_to_uint(i):
    return int(abs(round(i)))

def round_real_to_char(i):
    i = round_real_to_uint(i)
    if i < (1 << 8):
        return struct.pack('<B', i)
    if i < (1 << 16):
        return struct.pack('<H', i)
    if i < (1 << 32):
        return struct.pack('<I', i)
    if i < (1 << 64):
        return struct.pack('<Q', i)

def vectorize(a):
    res = []
    for v in list(a):
        res.append(ord(v))
    return vector(res) # pylint: disable=E0602