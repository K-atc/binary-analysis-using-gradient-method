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
        ### NOTE: `ld_path` is usable in Python3 (latest angr can't be installed in Python2)
        ### About `ld_path`: https://github.com/angr/cle/blob/master/README.md
        # self.proj = angr.Project(self.main_file, auto_load_libs=False, load_options={'force_load_libs': ['libmagic.so.1'], 'ld_path': ['/vagrant/sample2/file/src/.libs/']}) # FIXME
        self.proj = angr.Project(self.main_file, auto_load_libs=False, load_options={'force_load_libs': ['libmagic.so.1']})
        print("proj.loader.all_objects = {}".format(self.proj.loader.all_objects))
        self.cfg = self.proj.analyses.CFGFast() # CFGFast() misses predecessors not jointed to the block
        # self.cfg = self.proj.analyses.CFGEmulated() # Not works for external library (?)

    def __del__(self):
        self.stop()

    def get_tracee_mmap(self):
        self.mmap = self.process.readMappings()
        return self.mmap

    def get_tracee_object_base_addr(self, object_name):
        # if self.debug: print("[*] get_tracee_object_base_addr(object_name='{}')".format(object_name))
        if hasattr(self, "mmap") and not self.mmap:
            mmap = self.mmap
        else:
            mmap = self.get_tracee_mmap()
        assert object_name is not None
        assert mmap is not None
        object_name = os.path.basename(object_name)
        for x in mmap:
            if x.pathname and (object_name in os.path.basename(str(x.pathname))):
                # if self.debug: print("[*] get_tracee_object_base_addr: {:#x} {}".format(x.start, x.pathname))
                return x.start
        raise UnhandledCaseError("Cannot find base address of '{}'".format(object_name))

    def get_tracee_main_object_base_addr(self):
        return self.get_tracee_object_base_addr(self.main_file)

    def get_tracee_main_rebased_addr(self, relative_addr):
        if self.debug: print("self.tracee_main_object_base_addr = {:#x}".format(self.tracee_main_object_base_addr))
        if not self.tracee_main_object_base_addr:
            raise Exception("called get_tracee_main_rebased_addr() before running process")
        return self.tracee_main_object_base_addr + relative_addr

    ### REFACTER: object_name -> object_file
    def set_breakpoint(self, variable=None, object_name=None, relative_addr=None, rebased_addr=None):
        if rebased_addr and self.debug: print("[*] set_breakpoint(rebased_addr={:#x})".format(rebased_addr))
        if variable:
            assert variable, ir.Variable
            if self.debug: print("[*] set_breakpoint(variable={})".format(variable))
            if variable.objfile:
                rebased_addr = self.get_tracee_object_base_addr(variable.objfile) + variable.addr
            else:
                rebased_addr = self.get_tracee_main_object_base_addr() + variable.addr
        if relative_addr:
            if self.debug: print("[*] set_breakpoint(object_name='{}', relative_addr={:#x})".format(object_name, relative_addr))
            if not relative_addr < 0x400000:
                print("[!] set_breakpoint(object_name='{}', relative_addr={:#x}): relative_addr may be rebased address".format(object_name, relative_addr))
            if object_name:
                rebased_addr = self.get_tracee_object_base_addr(object_name) + relative_addr
            else:
                rebased_addr = self.tracee_main_object_base_addr + relative_addr
        if rebased_addr:
            try:
                return self.process.createBreakpoint(rebased_addr)
            except ProcessError as e:
                if variable:
                    marker = "{}".format(variable)
                else:
                    marker = "object={} ({:#x})".format(object_name, self.get_tracee_object_base_addr(object_name))
                self.process.dumpMaps()
                print("[!] Failed to set breakpoint: {}, rebased_address={:#x}".format(marker, rebased_addr))
                raise e
        raise UnhandledCaseError("set_breakpoint: provide rebased_addr or relative_addr")

    def run(self, args=[], stdin=b'', files={}, env={}):
        assert(isinstance(args, list))
        assert(isinstance(stdin, bytes))
        if self.debug: print("run(args={!r}, stdin={}, files={})".format(args, stdin, files))
        args = [self.main_file] + args
        self.args = args
        self.stdin = stdin
        self.breakpoints = []
        self.fs = FileSystem('./fs-{}/'.format(self.__class__.__name__))
        self.env = env

        for file_path, file_content in files.items():
            self.fs.create(file_path, data=file_content)

        ### create stdin
        ### TODO: Hook open & read syscall
        f_stdin = self.fs.create('.stdin', data=stdin)

        ### ptrace setup
        if self.debug:
            stdout = None
        else:
            stdout = subprocess.PIPE
        # env = {'LD_LIBRARY_PATH': '/vagrant/sample2/file/src/.libs/', 'LD_BIND_NOW': '1'} # FIXME
        if env is not {}:
            env = {'LD_LIBRARY_PATH': env['LD_LIBRARY_PATH'], 'LD_BIND_NOW': '1'} # FIXME
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
        main_b = self.set_breakpoint(object_name=self.main_file, relative_addr=main_addr)
        self.cont()
        main_b.desinstall(set_ip=True)
        self.get_tracee_mmap()

    def collect(self, y_variables):
        inspector = self
        breakpoint_addrs = sorted(set(map(lambda _: _.addr, y_variables)))
        if self.debug: print("[*] collect(): breakpoint_addrs = [{}]".format(', '.join("{:#x}".format(x) for x in breakpoint_addrs)))
        for v in set(y_variables):
            if v.addr in breakpoint_addrs:
                inspector.set_breakpoint(variable=v)
                breakpoint_addrs.remove(v.addr)
        y = {}
        while True:
            try:
                inspector.cont()
            except Exception as e: # pylint: disable=W0612
                # print(e)
                break
            if not inspector.is_tracee_attached():
                break
            pc = inspector.process.getInstrPointer()
            breakpoint_addr = pc - 1
            objfile = inspector.find_object_containing(tracee_rebased_addr=breakpoint_addr)
            addr = inspector.get_relative_addr(object_name=objfile, tracee_rebased_addr=breakpoint_addr)
            res = inspector.read_vars(y_variables.find(objfile=objfile, addr=addr))
            y.update(res)
            b = inspector.process.findBreakpoint(breakpoint_addr)
            if b:
                if self.debug: print("[*] remove breakpoint at {:#x}".format(b.address))
                b.desinstall(set_ip=True)
            ### Reinstall breakpoint
            inspector.process.singleStep()
            inspector.process.waitSignals(signal.SIGTRAP) # pylint: disable=E1101
            inspector.set_breakpoint(rebased_addr=breakpoint_addr)
        inspector.stop()
        return y

    def cont(self):
        if self.pid > 0:
            if self.debug: print("[*] cont():")
            try:
                self.process.cont()
                event = self.process.waitSignals(signal.SIGINT, signal.SIGTRAP) # pylint: disable=E1101
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
            self.mmap = None
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
                object_name = os.path.basename(object_name)
                base_addr = self.proj.loader.shared_objects[object_name].min_addr
            else:
                if rebased_addr > 0x2000000:
                    print("[!] get_relative_addr(object_name={}, rebased_addr={}, tracee_rebased_addr={}): May missing object_name".format(object_name, rebased_addr, tracee_rebased_addr))
                base_addr = self.proj.loader.main_object.min_addr
            return rebased_addr - base_addr
        if tracee_rebased_addr:
            if object_name:
                return tracee_rebased_addr - self.get_tracee_object_base_addr(object_name)
            else:
                return tracee_rebased_addr - self.tracee_main_object_base_addr
        raise UnhandledCaseError("provide rebased_addr or tracee_rebased_addr")

    def find_object_containing(self, rebased_addr=None, tracee_rebased_addr=None):
        if rebased_addr:
            return self.proj.loader.find_object_containing(rebased_addr).binary
        if tracee_rebased_addr:
            for x in self.mmap:
                if tracee_rebased_addr in x:
                    return x.pathname
            raise UnexpectedException("Memory map for address {:#x} not found in tracee".format(tracee_rebased_addr))
        raise UnhandledCaseError("provide rebased_addr or tracee_rebased_addr")

    def get_cfg_node_at(self, object_name=None, relative_addr=None, rebased_addr=None):
        if not relative_addr and not rebased_addr:
            raise UnhandledCaseError("get_cfg_node_insns_at: provide rebased_addr or relative_addr")
        if relative_addr:
            if self.debug: print("[*] get_cfg_node_at(object_name={}, relative_addr={:#x})".format(object_name, relative_addr))
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

    def get_cfg_node_insns_at(self, object_name=None, relative_addr=None, rebased_addr=None, node=None):
        if relative_addr:
            return list(self.get_cfg_node_at(object_name=None, relative_addr=relative_addr).block.capstone.insns)
        if rebased_addr:
            return list(self.get_cfg_node_at(object_name=None, rebased_addr=rebased_addr).block.capstone.insns)
        if node:
            return list(node.block.capstone.insns)
        raise UnhandledCaseError("get_cfg_node_insns_at: provide rebased_addr or relative_addr")

    def get_node_condition(self, node):
        def __collect_insns_ops(insn, object_file):
            v = []
            for i, op in enumerate(insn.operands): # pylint: disable=W0612
                insn_relative_address = self.get_relative_addr(object_name=object_file, rebased_addr=insn.address)
                if op.type == capstone.x86.X86_OP_REG:
                    v.append(ir.Variable(var(insn, op), op.size, insn_relative_address, ir.Register(insn.reg_name(op.reg)), object_file))
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
                    v.append(ir.Variable(var(insn, op), op.size, insn_relative_address, vmem, object_file))
            return v

        def __assign_constraint(insns, object_file):
            res = ir.ConstraintList()
            ### Assign instruction
            for insn in insns:
                if insn.id in [capstone.x86.X86_INS_MOV]:
                    v = __collect_insns_ops(insn, object_file)
                    res.append(ir.Assign(v[0], v[1]))
            return res

        def __call_function(inspector, insns, object_file):
            assert isinstance(inspector, Inspector)
            res = ir.ConstraintList()
            ### Call instruction
            for i, insn in enumerate(insns):
                call_f = None
                if insn.id in [capstone.x86.X86_INS_CALL]:
                    insn_relative_address = self.get_relative_addr(object_name=object_file, rebased_addr=insn.address)
                    func_addr = insn.operands[0].imm
                    func_name = inspector.proj.loader.find_plt_stub_name(func_addr)
                    ### REFACTER ME
                    if func_name == 'strncmp':
                        reg_name = ['rdi', 'rsi', 'edx']

                        ### Build function args
                        f_args = []
                        for i in range(3):
                            f_args.append(ir.Register(reg_name[i]))

                        ### Build real/virtual function return value
                        next_insn_addr = insn_relative_address + insn.size
                        next_insn = inspector.get_cfg_node_insns_at(rebased_addr=insn.address + insn.size)[0] # NOTE: angr (insns[i + 1]) returns `lea` (insn[i - 1])
                        ret_op = next_insn.operands[1]
                        if ret_op.type == capstone.x86.X86_OP_REG:
                            func_ret_reg_name = next_insn.reg_name(ret_op.reg)
                        elif ret_op.type == capstone.x86.X86_OP_MEM:
                            func_ret_reg_name = next_insn.reg_name(ret_op.mem.base)
                        else:
                            raise UnhandledCaseError("ret_op.type = {}".format(ret_op.type))
                        f_ret = ir.FuncCallRet(next_insn_addr, ir.Register(func_ret_reg_name))
                        r_ret = ir.Variable(var(next_insn, ret_op), ret_op.size, next_insn_addr, ir.Register(func_ret_reg_name), object_file)

                        call_f = ir.Strncmp(f_ret, f_args, insn_relative_address, object_file)
                    else:
                        raise UnhandledCaseError("Unhandled function call '{:#x}: call {}'".format(insn.address, func_name))
                    
                    res.append(ir.Assign(call_f.ret, call_f))
                    res.append(ir.Eq(r_ret, call_f.ret))
            return res

        def __jump_not_taken_constraint(insns, object_file):
            if len(node.successors) < 2:
                return ir.Top()
            else:
                compare_insn = insns[-2]
                jcc_insn = insns[-1]
                
                ### Compare Instruction
                for insn in [compare_insn]:
                    v = __collect_insns_ops(insn, object_file)
                    if insn.id in [capstone.x86.X86_INS_CMP, capstone.x86.X86_INS_TEST]:
                        left = v[0]
                        right = v[1]
                    if insn.id in [capstone.x86.X86_INS_MOV]:
                        left = v[0]
                        right = ir.Value(0)

                ### Conditional Branch
                for insn in [jcc_insn]:
                    if compare_insn.id in [capstone.x86.X86_INS_CMP, capstone.x86.X86_INS_MOV]:
                        # NOTE: Returns constraint of jump *not* taken
                        if insn.id == capstone.x86.X86_INS_JNE: # jnz
                            return ir.Eq(left, right)
                        if insn.id == capstone.x86.X86_INS_JE:  # jz
                            return ir.Ne(left, right)
                        if insn.id == capstone.x86.X86_INS_JA:  # left - right >= 0
                            return ir.Lt(left, right)
                        if insn.id == capstone.x86.X86_INS_JB:  # left - right < 0 # readlly?
                            return ir.Gt(left, right)
                        if insn.id == capstone.x86.X86_INS_JBE:  # left - right <= 0
                            return ir.Ge(left, right)
                        if insn.id == capstone.x86.X86_INS_JLE:  # left - right <= 0
                            return ir.Gt(left, right)
                    elif compare_insn.id == capstone.x86.X86_INS_TEST:
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
                        raise UnhandledCaseError("get_node_condition: Unhandled instruction '{:#x}: {} {}'".format(compare_insn.address, compare_insn.mnemonic, compare_insn.op_str))
                    raise UnhandledCaseError("get_node_condition: Unsupported instruction '{:#x}: {} {}'".format(insn.address, insn.mnemonic, insn.op_str))

        if self.debug: print("[*] get_node_condition: visited node {} (addr={:#x})".format(node, node.addr))

        object_file = self.find_object_containing(rebased_addr=node.addr)
        insns = self.get_cfg_node_insns_at(rebased_addr=node.addr)
        assert len(insns) > 0

        # assign_constraint = __assign_constraint(insns, object_file)
        assign_constraint = ir.ConstraintList()
        call_constraint = __call_function(self, insns, object_file)
        jump_not_taken_constraint = __jump_not_taken_constraint(insns, object_file)
        return assign_constraint + call_constraint + [jump_not_taken_constraint]

    # @return list of constriant IR
    def get_condition_at(self, tactic, object_name=None, relative_addr=None, rebased_addr=None):
        assert(callable(tactic))
        if not relative_addr and not rebased_addr:
            raise UnhandledCaseError("provide rebased_addr or relative_addr")
        if relative_addr:
            if object_name is None and relative_addr >= 0x400000:
                print("[!] get_condition_at(relative_addr={:#x}): Given relative_addr seems to be rebased address".format(relative_addr))
            node = self.get_cfg_node_at(object_name=object_name, relative_addr=relative_addr)
        if rebased_addr:
            node = self.get_cfg_node_at(rebased_addr=rebased_addr)
        return tactic(self, node)

    def get_prev_node(self, node):
        prev_addr = node.addr - 1
        if prev_addr < node.function_address:
            return None
        return self.get_cfg_node_at(rebased_addr=prev_addr)

    # @return bytes
    def read_mem(self, addr, size):
        return self.process.readBytes(addr, size)

    def read_var(self, var):
        if self.debug: print("[*] read_var({})".format(var))
        assert isinstance(var, ir.Variable)
        
        reg = self.process.getreg
        mem = self.process.readBytes
        op = var.vtype
        assert not isinstance(op, ir.NullType)
        if isinstance(op, ir.Register):
            return reg(op.name)
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
                if isinstance(var, ir.Call):
                    if isinstance(var, ir.Strncmp):
                        arg = [None] * len(var.args)
                        for i, v in enumerate(var.args):
                            value = self.read_var(v)
                            if self.debug:
                                res[v.name] = value
                            arg[i] = value
                        n = arg[2]
                        s1 = self.read_mem(arg[0], n)
                        s2 = self.read_mem(arg[1], n)
                        res[var.n.name] = n
                        res[var.s1.name] = s1
                        res[var.s2.name] = s2               
                    else:
                        import ipdb; ipdb.set_trace()
                        raise UnhandledCaseError("missing ir.Call case: {}".format(var))
                elif isinstance(var, ir.FuncArg):
                    pass # Do not need to read value. They are processed in `Call` case
                else:
                    res[var.name] = self.read_var(var)
            return res
        else:
            raise ProcessNotFoundError("Tracee is not attached")

class Tactic:
    @staticmethod
    def near_path_constraint(inspector, node):
        # print("node = {}".format(node))
        # print("node.predecessors = {}".format(node.predecessors))
        predecessors = []
        if node.predecessors:
            predecessors += node.predecessors
        if node.predecessors:
            prev_node = inspector.get_prev_node(node)
            if prev_node:
                predecessors.append(prev_node)
                if prev_node.predecessors:
                    predecessors += prev_node.predecessors
            for pnode in node.predecessors:
                prev = inspector.get_prev_node(pnode)
                if prev:
                    predecessors.append(prev)
            # import ipdb; ipdb.set_trace()

        predecessors_conditions = ir.ConstraintList()
        predecessors = set(predecessors)
        for predecessor in predecessors:
            assert predecessor is not None
            if predecessor.is_simprocedure: # skip symbolic procedure (simprocedure is introduced by angr)
                continue
            predecessor_condition = inspector.get_node_condition(predecessor)
            if predecessor_condition != ir.Top():
                predecessors_conditions += predecessor_condition
        node_constraint = inspector.get_node_condition(node)            
        return predecessors_conditions + node_constraint

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