import os
import signal
import subprocess
import struct
import time
import functools

import ptrace.debugger
import ptrace.error
from ptrace.debugger.process_event import ProcessEvent, NewProcessEvent, ProcessExit
import angr
import capstone

### BUGFIX: Incorrect sub register definition in python-ptrace
from ptrace.binding.cpu import CPU_SUB_REGISTERS # debug
CPU_SUB_REGISTERS['eax'] = ('rax', 0, 0xffffffff)
CPU_SUB_REGISTERS['ebx'] = ('rbx', 0, 0xffffffff)
CPU_SUB_REGISTERS['ecx'] = ('rcx', 0, 0xffffffff)
CPU_SUB_REGISTERS['edx'] = ('rdx', 0, 0xffffffff)
CPU_SUB_REGISTERS['r13d'] = ('r13', 0, 0xffffffff)

from .ast import constraint as ir
from .exceptions import *
from .fs import FileSystem
# from .encoder import Encode

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

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

class Inspector:
    def __init__(self, main_file, debug=False):
        self.main_file = main_file
        self.debug = debug
        self.pid = -1
        self.tracee_main_object_base_addr = 0

        ### angr setup
        self.proj = angr.Project(self.main_file, auto_load_libs=False, load_options={'force_load_libs': ['libmagic.so.1.0.0'], 'ld_path': ['/vagrant/sample2/file/src/.libs/']})
        print(self.proj.loader.all_objects)
        # print(dir(self.proj.loader.all_objects[0]))
        # exit(1)
        self.cfg = self.proj.analyses.CFGFast()

    def __del__(self):
        self.stop()

    def get_tracee_mmap(self):
        self.mmap = self.process.readMappings()
        return self.mmap

    def get_tracee_object_base_addr(self, object_name):
        if hasattr(self, "mmap") and self.mmap:
            mmap = self.mmap
        else:
            mmap = self.get_tracee_mmap()
        for x in mmap:
            if x.pathname and object_name in str(x.pathname):
                if self.debug: print("{:#x} {}".format(x.start, x.pathname))
                return x.start
        raise UnhandledCaseError("get_main_base_addr: Cannot find {} base address".format(object_name))

    def get_tracee_main_object_base_addr(self):
        return self.get_tracee_object_base_addr(self.main_file)

    def get_tracee_main_rebased_addr(self, relative_addr):
        print("self.tracee_main_object_base_addr = {:#x}".format(self.tracee_main_object_base_addr))
        if not self.tracee_main_object_base_addr:
            raise Exception("called get_tracee_main_rebased_addr() before running process")
        return self.tracee_main_object_base_addr + relative_addr

    ### TODO: support ast.constriant.Variable
    def set_breakpoint(self, variable=None, object_name=None, relative_addr=None, rebased_addr=None):
        if variable:
            assert variable, ir.Variable
            raise NotImplementedError("set_breakpint: TODO: support ast.constriant.Variable")
        if relative_addr:
            if self.debug: print("[*] set_breakpoint(object_name={}, relative_addr={:#x})".format(object_name, relative_addr))
            if object_name:
                return self.process.createBreakpoint(self.get_tracee_object_base_addr(object_name) + relative_addr)
            else:
                return self.process.createBreakpoint(self.tracee_main_object_base_addr + relative_addr)
        if rebased_addr:
            if self.debug: print("[*] set_breakpoint(rebased_addr={:#x})".format(rebased_addr))
            return self.process.createBreakpoint(rebased_addr)
        raise UnhandledCaseError("set_breakpoint: provide rebased_addr or relative_addr")

    def run(self, args=[], stdin=b'', files={}):
        assert(isinstance(args, list))
        assert(isinstance(stdin, bytes))
        if self.debug: print("run(args={!r}, stdin={}, files={})".format(args, stdin, files))
        args = [self.main_file] + args
        self.args = args
        self.stdin = stdin
        self.breakpoints = []
        self.fs = FileSystem('./fs-{}/'.format(self.__class__.__name__))

        if files != {}:
            raise NotImplementedError("files is not supported")

        ### create stdin
        ### TODO: Hook open & read syscall
        f_stdin = self.fs.create('stdin', data=stdin)

        ### ptrace setup
        if self.debug:
            stdout = None
        else:
            stdout = subprocess.PIPEfile
        env = {'LD_LIBRARY_PATH': '/vagrant/sample2/file/src/.libs/', 'LD_BIND_NOW': '1'} # FIXME
        self.tracee = subprocess.Popen(args, stdin=f_stdin, stdout=stdout, env=env)
        self.pid = self.tracee.pid
        self.debugger = ptrace.debugger.PtraceDebugger()
        if self.debug: print("[*] Attach the running process %s" % self.pid)
        try:
            self.process = self.debugger.addProcess(self.pid, False)     
        except (ptrace.error.PtraceError, ProcessExit) as e:
            print("[!] Can't attach to process (pid={}): {}".format(self.pid, e))
            exit(1)

        ### Get base address of traee's main object
        self.tracee_main_object_base_addr = self.get_tracee_main_object_base_addr()

        ### Execute to main() to laod all external libraries
        main_addr = self.find_symbol("main").relative_addr
        self.set_breakpoint(object_name=self.main_file, relative_addr=main_addr)
        self.cont()
        self.get_tracee_mmap()


    def cont(self):
        if self.pid > 0:
            if self.debug: print("[*] cont():")
            try:
                self.process.cont()
                event = self.process.waitSignals(signal.SIGINT, signal.SIGTRAP)
                if self.debug: print("Recieved event={}".format(event))
                if self.debug: print("[*] handled signal")
            except ProcessExit as event:
                if self.debug: print("Process exited with exitcode {} by signal {}: {}".format(event.exitcode, event.signum, event))
                self.stop()
                raise event
            except ProcessEvent as event:
                print("Recieved event {}".format(event))
                # if self.debug: self.process.dumpMaps()
                if self.debug: self.process.dumpRegs()
                # if self.debug: self.process.dumpStack()
                raise event
            except Exception as e:
                print("[!] Exception {}".format(e))
        else:
            print("[!] proess is not running")
            return False

    def stop(self):
        if hasattr(self, "process") and  self.is_tracee_attached():
            if self.debug: print("[*] Detaching process (pid={})".format(self.pid))
            self.process.detach()
            self.debugger.quit()
            self.pid = -1
        if not self.debug:
            try:
                self.tracee.kill()
            except:
                pass

    def is_tracee_attached(self):
        return self.process.is_attached

    def find_symbol(self, symbol_name):
        symbol = self.proj.loader.find_symbol(symbol_name)
        if symbol:
            return symbol
        else:
            raise UnexpectedException("find_symbol: symbol '{}' not found".format(symbol_name))

    def get_relative_addr(self, object_name=None, rebased_addr=None, tracee_rebased_addr=None):
        if rebased_addr:
            if object_name:
                base_addr = self.proj.loader.shared_objects[object_name].min_addr
            else:
                base_addr = self.proj.loader.main_object.min_addr
            return rebased_addr - base_addr
        if tracee_rebased_addr:
            if object_name:
                return tracee_rebased_addr - self.get_tracee_object_base_addr(object_name)
            else:
                return tracee_rebased_addr - self.tracee_main_object_base_addr
        raise UnhandledCaseError("get_relative_addr")

    def get_cfg_node_at(self, object_name=None, relative_addr=None, rebased_addr=None):
        if not relative_addr and not rebased_addr:
            raise UnhandledCaseError("get_cfg_node_code_at: provide rebased_addr or relative_addr")
        if relative_addr:
            if object_name:
                addr = self.proj.loader.shared_objects[object_name].min_addr + relative_addr
            else:
                addr = self.proj.loader.main_object.min_addr + relative_addr
        if rebased_addr:
            addr = rebased_addr
        try:
            addr = int(addr)
        except:
            UnexpectedException("addr is not kind of integer: addr = {:#x} ({})".format(addr, type(addr)))
        res = self.cfg.get_any_node(addr, anyaddr=True)
        if res is None:
            raise InvalidAddressError("get_cfg_node_at: Basic block starts with provided address {:#x} does not exist".format(addr))
        return res

    def get_cfg_node_code_at(self, object_name=None, relative_addr=None, rebased_addr=None, node=None):
        if relative_addr:
            return self.get_cfg_node_at(object_name=None, relative_addr=relative_addr).byte_string
        if rebased_addr:
            return self.get_cfg_node_at(object_name=None, rebased_addr=rebased_addr).byte_string
        if node:
            return node.byte_string
        raise UnhandledCaseError("get_cfg_node_code_at: provide rebased_addr or relative_addr")

    def get_node_condition(self, node):
        if self.debug: print("[*] get_node_condition: visited node {} (addr={:#x})".format(node, node.addr))
        if len(node.successors) < 2:
            return ir.Top()
        else:
            ### TODO: Object name
            start_addr = node.addr - self.proj.loader.find_object_containing(node.addr).min_addr
            code = self.get_cfg_node_code_at(rebased_addr=node.addr)
            insns = list(md.disasm(code, start_addr))

            ### Compare instruction
            v = []
            compare_inst = insns[-2]
            for insn in [insns[-2]]:
                for c, op in enumerate(insn.operands):                
                    if op.type == capstone.x86.X86_OP_REG:
                        v.append(ir.Variable(var(insn, op), op.size, insn.address, ir.Register(insn.reg_name(op.reg))))
                    if op.type == capstone.x86.X86_OP_IMM:
                        v.append(ir.Value(op.imm))
                    if op.type == capstone.x86.X86_OP_MEM:
                        if op.mem.index:
                            reg_index = ir.Register(insn.reg_name(op.mem.index))
                        else:
                            reg_index = None
                        vmem = ir.Memory(
                            ir.Register(insn.reg_name(op.mem.base)),
                            reg_index,
                            op.mem.scale,
                            op.mem.disp
                            )
                        v.append(ir.Variable(var(insn, op), op.size, insn.address, vmem))
                if insn.id in [capstone.x86.X86_INS_CMP, capstone.x86.X86_INS_TEST]:
                    left = v[0]
                    right = v[1]
                if insn.id in [capstone.x86.X86_INS_MOV]:
                    left = v[0]
                    right = ir.Value(0)

            ### Conditional Branch
            for insn in [insns[-1]]:
                if compare_inst.id in [capstone.x86.X86_INS_CMP, capstone.x86.X86_INS_MOV]:
                    # NOTE: Returns constraint of jump *not* taken
                    if insn.id == capstone.x86.X86_INS_JNE: # jnz
                        return ir.Eq(left, right)
                    if insn.id == capstone.x86.X86_INS_JE:  # jz
                        return ir.Ne(left, right)
                    if insn.id == capstone.x86.X86_INS_JA:  # left - right >= 0
                        return ir.Lt(left, right)
                    if insn.id == capstone.x86.X86_INS_JB:  # left - right < 0
                        return ir.Gt(left, right)
                elif compare_inst.id == capstone.x86.X86_INS_TEST:
                    if left == right:
                        if insn.id == capstone.x86.X86_INS_JNE: # jnz
                            return ir.Eq(left, ir.Value(0))
                        if insn.id == capstone.x86.X86_INS_JE:  # jz
                            return ir.Ne(left, ir.Value(0))
                    else:
                        if insn.id == capstone.x86.X86_INS_JNE: # jnz
                            return ir.Eq(ir.Band(left, right), ir.Value(0))
                        if insn.id == capstone.x86.X86_INS_JE:  # jz
                            return ir.Ne(ir.Band(left, right), ir.Value(0))
                else:
                    raise UnhandledCaseError("get_node_condition: Unhandled instruction '{:#x}: {} {}'".format(compare_inst.address, compare_inst.mnemonic, compare_inst.op_str))
                raise UnhandledCaseError("get_node_condition: Unsupported instruction '{:#x}: {} {}'".format(insn.address, insn.mnemonic, insn.op_str))

    # @return list of constriant IR
    def get_condition_at(self, tactic, object_name=None, relative_addr=None, rebased_addr=None):
        assert(callable(tactic))
        if not relative_addr and not rebased_addr:
            raise UnhandledCaseError("get_cfg_node_code_at: provide rebased_addr or relative_addr")
        if relative_addr:
            node = self.get_cfg_node_at(object_name=object_name, relative_addr=relative_addr)
        if rebased_addr:
            node = self.get_cfg_node_at(object_name=object_name, rebased_addr=rebased_addr)
        return tactic(self, node)

    def read_var(self, var):
        if self.debug: print("[*] read_var({})".format(var))
        assert(isinstance(var, ir.Variable))
        reg = self.process.getreg
        mem = self.process.readBytes
        op = var.vtype
        if isinstance(op, ir.Register):
            return reg(var.vtype.name)
        if isinstance(op, ir.Memory):
            if op.index:
                addr = reg(op.base.name) + reg(op.index.name) * op.scale + op.disp
            else:
                addr = reg(op.base.name) + op.disp
            return bytes_to_uint(mem(addr, var.size), var.size)

    # @return variables value in current context of tracee
    def read_vars(self, _vars):
        if self.is_tracee_attached():
            assert(isinstance(_vars, ir.VariableList))
            res = {}
            for var in _vars:
                res[var.name] = self.read_var(var)
            return res
        else:
            raise ProcessNotFoundError("Tracee is not attached")

class Tactic:
    @staticmethod
    def near_path_constraint(inspector, node):
        predecessors_conditions = ir.ConstraintList()
        for predecessor in node.predecessors:
            predecessor_condition = inspector.get_node_condition(predecessor)
            if predecessor_condition != ir.Top():
                predecessors_conditions.append(predecessor_condition)
        node_constraint = inspector.get_node_condition(node)
        if node_constraint == ir.Top():
            return predecessors_conditions
        else:
            return predecessors_conditions + ir.ConstraintList([node_constraint])

class X():
    def __init__(self, args=[], stdin='', files={}):
        assert isinstance(args, list)
        assert isinstance(stdin, str)
        self.args = args
        self.stdin = stdin
        self.files = files

    def __repr__(self):
        return "{}(args={!r}, stdin={!r}, files={!r})".format(self.__class__.__name__, self.args, self.stdin, self.files)

class Program:
    # @param xadapter encodes vector to vales of x variables (program inputs)
    # @param yadapter encodes values of y variables to vector
    def __init__(self, program, xadapter, yadapter, debug=False):
        assert isinstance(program, str), "'program` must be a path to program"
        assert callable(xadapter), "`adapter` must be a fucntion"
        self.program = program
        self.xadapter = xadapter
        self.yadapter = yadapter
        # self.inspector = Inspector(program, debug=True)
        self.inspector = Inspector(program, debug=False)
        self.debug = debug

    def get_constraints(self, tactic, object_name=None, relative_addr=None, rebased_addr=None):
        if relative_addr:
            return self.inspector.get_condition_at(tactic, object_name=object_name, relative_addr=relative_addr)
        if rebased_addr:
            return self.inspector.get_condition_at(tactic, object_name=object_name, rebased_addr=rebased_addr)
        raise UnhandledCaseError("provide relative_addr or rebased_addr")

    def N(self, constraint):
        assert isinstance(constraint, ir.ConstraintIR)
        return functools.partial(self.call_with_adapter, constraint.get_variables())
    
    def L(self, constraint):
        assert isinstance(constraint, ir.ConstraintIR)
        return Encode(constraint)

    def call(self, y_variables, x):
        if self.debug: print("[*] call(y=..., x={})".format(x))
        assert isinstance(x, X), "x must be instance of X: x = {}".format(x)

        inspector = self.inspector
        breakpoint_addrs = sorted(set(map(lambda _: _.addr, y_variables)))

        inspector.run(args=x.args, stdin=x.stdin, files={})
        y = {}
        for addr in breakpoint_addrs:
            b = inspector.set_breakpoint(relative_addr=addr)
        while True:
            try:
                inspector.cont()
            except Exception as e:
                # print(e)
                break
            if not inspector.is_tracee_attached():
                break
            pc = self.inspector.process.getInstrPointer()
            # if self.debug: print("[*] stopped by breakpoint. pc = {:#x}".format(pc))
            addr = self.inspector.get_relative_addr(tracee_rebased_addr=pc - 1)
            res = inspector.read_vars(y_variables.find(addr=addr))
            # if self.debug: print("[*] read_var() = {}".format(res))
            y.update(res)
            b = self.inspector.process.findBreakpoint(pc - 1)
            if b:
                print("!")
                if self.debug: print("[*] remove breakpoint at {:#x}".format(b.address))
                b.desinstall(set_ip=True)
            ### Reinstall breakpoint
            self.inspector.process.singleStep()
            # self.inspector.cont()
            self.inspector.process.waitSignals(signal.SIGTRAP)
            inspector.set_breakpoint(relative_addr=addr)


        inspector.stop()
        if self.debug: print("y = {}".format(y))
        return y

    def call_with_adapter(self, y_variables, x):
        # print("call_with_adpter: x = {}".format(x))
        return self.yadapter(y_variables, self.call(y_variables, self.xadapter(x)))

    def run(self, x):
        assert(isinstance(x, X))
        if self.debug: print("run(x={})".format(x))
        args = [self.program] + x.args

        if x.files != {}:
            raise NotImplementedError("files is not supported")

        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return p.communicate(x.stdin)

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