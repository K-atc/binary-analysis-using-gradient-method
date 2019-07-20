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

from .ast import constraint as ir
from .exceptions import *
from .fs import FileSystem

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

### REFECTOR: tectic.py
class Tactic:
    @staticmethod
    def near_path_constraint(inspector, node):
        print("[*] near_path_constraint(node={})".format(node))
        # print("node.predecessors = {}".format(node.predecessors))
        predecessors = []
        if node.predecessors:
            predecessors += node.predecessors

            # If predecessor is called function node, add function call node as predecessor
            for pnode in node.predecessors:
                print("[*] {} -> successors = {}".format(pnode, pnode.successors))
                if pnode.addr == pnode.function_address: # If p is entory node of calld function,
                    prev_node = inspector.get_prev_node(node)
                    if prev_node:
                        predecessors.append(prev_node) # add function call node as predecessor.
                        if prev_node.predecessors:
                            predecessors += prev_node.predecessors
                    break
        # import ipdb; ipdb.set_trace()

        ### NOTE: Incerrect implementation for get_prev_node()
        for pnode in node.predecessors:
            prev = inspector.get_prev_node(pnode)
            if prev:
                predecessors.append(prev)

        predecessors_conditions = ir.ConstraintList()
        predecessors = set(predecessors)
        print("[*] Tactic.near_path_constraint: predecessors = {}".format(predecessors))
        for predecessor in predecessors:
            assert predecessor is not None
            if predecessor.is_simprocedure: # skip symbolic procedure (simprocedure is introduced by angr)
                continue
            jumps_on_branch = False
            if len(predecessor.successors) == 2: # Conditional Branch
                # import ipdb; ipdb.set_trace()
                if predecessor.addr + predecessor.size == node.addr: # takes no jump (sequential nodes)
                    jumps_on_branch = False
                else:
                    jumps_on_branch = True
            predecessor_condition = inspector.get_node_condition(predecessor, jumps_on_branch)
            if predecessor_condition != ir.Top():
                predecessors_conditions += predecessor_condition
        # node_constraint = inspector.get_node_condition(node)     
        # return predecessors_conditions + node_constraint
        return predecessors_conditions

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