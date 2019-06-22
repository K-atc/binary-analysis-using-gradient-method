import ptrace.debugger
from ptrace.debugger.process_event import *
import os
import signal
import angr
import capstone
import subprocess
import struct
import time

import ir
from exceptions import *
from fs import FileSystem

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
    return "{:x}_{}_{:}".format(addr, var_type, value)

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
    def __init__(self, main_file, debug=True):
        self.main_file = main_file
        self.debug = debug
        self.pid = -1
        self.tracee_main_object_base_addr = 0

        ### angr setup
        self.proj = angr.Project(self.main_file, load_options={'auto_load_libs': False})
        self.cfg = self.proj.analyses.CFGFast()

    def __del__(self):
        self.stop()

    def get_tracee_main_object_base_addr(self):
        mmap = self.process.readMappings()
        for x in mmap:
            if x.pathname and self.main_file in str(x.pathname):
                if self.debug: print("{:#x} {}".format(x.start, x.pathname))
                return x.start
        raise UnhandledCaseError("get_main_base_addr: Cannot find main object base address")

    def get_tracee_main_rebased_addr(self, relative_addr):
        print("self.tracee_main_object_base_addr = {:#x}".format(self.tracee_main_object_base_addr))
        if not self.tracee_main_object_base_addr:
            raise Exception("called get_tracee_main_rebased_addr() before running process")
        return self.tracee_main_object_base_addr + relative_addr

    def set_breakpoint(self, relative_addr=None, rebased_addr=None):
        if relative_addr:
            if self.debug: print("[*] set_breakpoint(relative_addr={:#x})".format(relative_addr))
            return self.process.createBreakpoint(self.tracee_main_object_base_addr + relative_addr)
        if rebased_addr:
            if self.debug: print("[*] set_breakpoint(rebased_addr={:#x})".format(rebased_addr))
            return self.process.createBreakpoint(rebased_addr)
        raise UnhandledCaseError("set_breakpoint: provide rebased_addr or relative_addr")

    # def run_tracee(self, args):
    #     pid = os.fork()
    #     if pid: # Parent process
    #         return pid
    #     else:
    #         time.sleep(1) # Wait for ptrace attach
    #         print("spawn child process...")
    #         try:
    #             os.execv(args[0], args)
    #         except OSError as e:
    #             print(e)
    #             exit(1)

    # def run_tracee(self, args, stdin):
    #     pid = os.fork()
    #     if pid: # Parent process
    #         print("[*] pid of Child process is {}".format(pid))
    #         return pid
    #     else:
    #         time.sleep(1) # Wait for ptrace attach
    #         print("spawn child process '{}' with {} ...".format(args, stdin))
    #         try:
    #             subprocess.Popen(args, stdin=stdin)
    #             while True:
    #                 pass
    #         except OSError as e:
    #             print(e)
    #             exit(1)

    def run(self, args=[], stdin=b'', files={}):
        assert(isinstance(args, list))
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
        # self.tracee = subprocess.Popen(args, stdin=f_stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.tracee = subprocess.Popen(args, stdin=f_stdin)
        self.pid = self.tracee.pid
        self.debugger = ptrace.debugger.PtraceDebugger()
        if self.debug: print("[*] Attach the running process %s" % self.pid)
        self.process = self.debugger.addProcess(self.pid, False)
        self.tracee_main_object_base_addr = self.get_tracee_main_object_base_addr()

    def cont(self):
        if self.pid > 0:
            if self.debug: print("[*] cont():")
            self.process.cont()
            try:
                event = self.process.waitSignals(signal.SIGINT, signal.SIGTRAP)
                if self.debug: print("Recived event={}".format(event))
                if self.debug: print("[*] handled signal")
            except ProcessExit as event:
                print("Process exited with exitcode {} by signal {}: {}".format(event.exitcode, event.signum, event))
                self.stop()
                raise event
            except ProcessEvent as event:
                print("Recieved event {}".format(event))
                self.process.dumpMaps()
                self.process.dumpRegs()
                # self.process.dumpStack()
                raise event
        else:
            print("[!] proess is not running")
            return False

    def stop(self):
        if hasattr(self, "process") and  self.is_tracee_attached():
            if self.debug: print("[*] Detaching process (pid={})".format(self.pid))
            self.process.detach()
            self.debugger.quit()
            self.pid = -1
            # self.tracee.kill() $ TODO

    def is_tracee_attached(self):
        return self.process.is_attached

    def find_symbol(self, symbol):
        return self.proj.loader.find_symbol(symbol)

    def get_relative_addr(self, rebased_addr=None):
        if rebased_addr:
            return rebased_addr - self.proj.loader.main_object.min_addr
        raise UnhandledCaseError("get_relative_addr")

    def get_cfg_node_at(self, relative_addr=None, rebased_addr=None):
        if not relative_addr and not rebased_addr:
            raise UnhandledCaseError("get_cfg_node_code_at: provide rebased_addr or relative_addr")
        if relative_addr:
            addr = self.proj.loader.main_object.min_addr + relative_addr
        if rebased_addr:
            addr = rebased_addr
        assert isinstance(addr, int) or isinstance(addr, long), "addr = {:#x} ({})".format(addr, type(addr))
        res = self.cfg.get_any_node(addr, anyaddr=True)
        if res is None:
            raise InvalidAddressError("get_cfg_node_at: Basic block starts with provided address {:#x} does not exist".format(addr))
        return res

    def get_cfg_node_code_at(self, relative_addr=None, rebased_addr=None, node=None):
        if relative_addr:
            return self.get_cfg_node_at(relative_addr=relative_addr).byte_string
        if rebased_addr:
            return self.get_cfg_node_at(rebased_addr=rebased_addr).byte_string
        if node:
            return node.byte_string
        raise UnhandledCaseError("get_cfg_node_code_at: provide rebased_addr or relative_addr")

    def get_node_condition(self, node):
        if self.debug: print("[*] get_node_condition: visited node {} (addr={:#x})".format(node, node.addr))
        if len(node.successors) < 2:
            return ir.Top()
        else:
            start_addr = self.get_relative_addr(rebased_addr=node.addr)
            code = self.get_cfg_node_code_at(rebased_addr=node.addr)
            insns = list(md.disasm(code, start_addr))
            ### Compare
            v = []
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
            ### Conditional Branch
            for insn in [insns[-1]]:
                if insn.id == capstone.x86.X86_INS_JNE:
                    return ir.Not(ir.Eq(left, right))
                if insn.id == capstone.x86.X86_INS_JE:
                    return ir.Eq(left, right)
                raise UnhandledCaseError("Unsupported instrunction '{} {}'".format(insns[-1].mnemonic, insns[-1].op_str))

    # @return list of constriant IR
    def get_condition_at(self, tactic, relative_addr=None, rebased_addr=None):
        assert(callable(tactic))
        if not relative_addr and not rebased_addr:
            raise UnhandledCaseError("get_cfg_node_code_at: provide rebased_addr or relative_addr")
        if relative_addr:
            node = self.get_cfg_node_at(relative_addr=relative_addr)
        if rebased_addr:
            node = self.get_cfg_node_at(rebased_addr=rebased_addr)
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
    def __init__(self, program, xadapter, yadapter, debug=True):
        assert isinstance(program, str), "'program` must be a path to program"
        assert callable(xadapter), "`adapter` must be a fucntion"
        self.program = program
        self.xadapter = xadapter
        self.yadapter = yadapter
        self.inspector = util.Inspector(program)
        self.debug = debug

    def get_constraints(tactic, relative_addr=None):
        if relative_addr:
            return inspector.get_condition_at(tactic, relative_addr=find_addr)
        raise UnhandledCaseError("provide relative_addr")

    def set_y_constraints(constraints):
        self.constraints = constraints
        self.y_variables = constraints.get_variables()

    def call(self, x):
        assert isinstance(x, X), "x must be instance of X: x = {}".format(x)

        inspector = self.inspector
        breakpoint_addrs = sorted(set(map(lambda _: _.addr, self.y_variables)))

        inspector.run(args=[self.program] + x.args, stdin=x.stdin, files={})
        y = {}
        for addr in breakpoint_addrs:
            b = inspector.set_breakpoint(relative_addr=addr)
            if self.debug: print("breakpioint address = {:#x}".format(b.address))
            try:
                inspector.cont()
            except Exception as e:
                print(e)
                break
            b.desinstall(set_ip=True)
            if not inspector.is_tracee_attached():
                break

            res = inspector.read_vars(variables.find(addr=addr))
            if self.debug: print("[*] read_var() = {}".format(res))
            y.update(res)
        return y

    def call_with_adapter(self, x):
        # print("call_with_adpter: x = {}".format(x))
        return self.yadapter(self.y_variables, self.call(self.xadapter(x)))

def strip_null(s):
    first_null_pos = s.find('\x00')
    return s[:first_null_pos]

def vector_to_string(v):
    try:
        s = ''.join(map(lambda _: chr(_) if _ > 0 else '\x00', v.list()))
        return s
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, v))
        traceback.print_exc()
        print("-> v = {}".format(v))
        exit(1)

class Statistics:
    lap_time = []
    start_time = 0

    def __init__(self):
        pass

    def lap_start(self):
        self.start_time = time.time()
    
    def lap_end(self):
        end_time = time.time()
        self.lap_time.append(end_time - self.start_time)
