import os
import sys
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

from .util import var, bytes_to_uint
from .ast import constraint as ir
from .exceptions import *
from .fs import FileSystem
from .breakpoint_manager import BreakpointManager


class Inspector:
    def __init__(self, main_file, debug=False):
        self.main_file = main_file
        self.debug = debug
        self.pid = -1
        self.tracee_main_object_base_addr = 0

        ### angr setup
        ### NOTE: `ld_path` is usable in Python3 (latest angr can't be installed in Python2)
        ### About `ld_path`: https://github.com/angr/cle/blob/master/README.md
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

    def get_tracee_rebased_addr(self, object_name, relative_addr):
        return self.get_tracee_object_base_addr(object_name) + relative_addr

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
        if isinstance(files, FileSystem):
            self.fs = files
        else:
            self.fs = FileSystem('./fs-{}/'.format(self.__class__.__name__)) # To be deprecated
        self.env = env

        ### Setup file system
        ### REFACTOR: Discontinue dict type
        if isinstance(files, dict):
            for file_path, file_content in files.items():
                self.fs.create(file_path, data=file_content)

        ### create stdin
        self.fs.create('.stdin', data=stdin)
        f_stdin = self.fs.open('.stdin')

        ### create stdout
        self.fs.create('.stdout', data=stdin)
        f_stdout = self.fs.open('.stdout')

        ### ptrace setup
        self.tracee = subprocess.Popen(args, stdin=f_stdin, stdout=f_stdout, env=env)
        self.pid = self.tracee.pid
        self.debugger = ptrace.debugger.PtraceDebugger()
        if self.debug: print("[*] Attach the running process %s" % self.pid)
        try:
            self.process = self.debugger.addProcess(self.pid, False)     
        except (ptrace.error.PtraceError, ProcessExit) as e:
            print("[!] Can't attach to process (pid={}): {}".format(self.pid, e))
            raise e

        ### Get base address of traee's main object
        self.tracee_main_object_base_addr = self.get_tracee_main_object_base_addr()

        ### Execute to main() to laod all external libraries
        main_addr = self.find_symbol("main").relative_addr
        main_b = self.set_breakpoint(object_name=self.main_file, relative_addr=main_addr)
        try:
            self.cont()
        except (ProcessExit) as e:
            print("[!] Unexpected process exit before reaching main() (pid={}): {}".format(self.pid, e))
            sys.stdout.flush()
            raise e
        main_b.desinstall(set_ip=True)
        self.get_tracee_mmap()

    def collect(self, y_constraints):
        def __read_var_hook(inspector, breakpoint_addr, y):
            objfile = inspector.find_object_containing(tracee_rebased_addr=breakpoint_addr)
            addr = inspector.get_relative_addr(object_name=objfile, tracee_rebased_addr=breakpoint_addr)
            res = inspector.read_vars(y_variables.find(objfile=objfile, addr=addr))
            return y.update(res)

        def __assume_eq_hook(inspector, breakpoint_addr, y):
            if inspector.debug: print("[*] __assume_eq_hook(breakpoint_addr={:#x})".format(breakpoint_addr))
            inspector.process.setreg('zf', 1)

        def __assume_ne_hook(inspector, breakpoint_addr, y):
            if inspector.debug: print("[*] __assume_ne_hook(breakpoint_addr={:#x})".format(breakpoint_addr))
            inspector.process.setreg('zf', 0)


        inspector = self
        y_variables = y_constraints.get_variables()

        breakpoint_manager = BreakpointManager(inspector)

        ### Set breakpoint for read_ver
        for v in set(y_variables):
            breakpoint_manager.set_breakpoint(__read_var_hook, variable=v)

        ### Set breakpoint for Assume node
        for node in y_constraints.get_assume_nodes():
            ### Skip blanknode
            if isinstance(node.value, ir.Top):
                break

            if isinstance(node.value, ir.Eq):
                hook = __assume_eq_hook
            elif isinstance(node.value, ir.Ne):
                hook = __assume_ne_hook
            else:
                raise UnhandledCaseError("Unhandled Assume node: {}".format(node))
            
            if isinstance(node.value.left, ir.Variable):
                v = node.value.left
            elif isinstance(node.value.right, ir.Variable):
                v = node.value.right
            else:
                raise UnexpectedException("Expected left or right hand of Assume node has Variable node: {}".format(node.value))

            object_name = v.objfile
            rebased_addr = inspector.get_cfg_node_at(object_name=object_name, relative_addr=v.addr).instruction_addrs[-1] # NOTE: conditional jump insn rebased address
            relative_addr = inspector.get_relative_addr(object_name=object_name, rebased_addr=rebased_addr)
            breakpoint_manager.set_breakpoint(hook, object_name=object_name, relative_addr=relative_addr)

        y = {}
        while True:
            try:
                inspector.cont()
            except Exception as e: # pylint: disable=W0612
                break
            if not inspector.is_tracee_attached():
                break

            ### Process breakpoint hook
            pc = inspector.process.getInstrPointer()
            breakpoint_addr = pc - 1
            for hook in breakpoint_manager.get_hook(breakpoint_addr):
                hook(inspector, breakpoint_addr, y)

            ### Remove breakpoint
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
                sys.stdout.flush()
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
        if self.is_tracee_attached():
            if self.debug: print("[*] Detaching process (pid={})".format(self.pid))
            self.process.detach()
            self.debugger.quit()
            del self.process
            del self.debugger
            self.pid = -1
            self.mmap = None
        if hasattr(self, "tracee"):
            if self.tracee.stdout:
                self.tracee.stdout.close()
            if self.tracee.stderr:
                self.tracee.stderr.close()
            try:
                self.tracee.terminate()
            except:
                pass

    def is_tracee_attached(self):
        if hasattr(self, "process"):
            return self.process.is_attached
        else:
            return False

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
                try:
                    object_name = os.path.basename(object_name)
                    addr = self.proj.loader.shared_objects[object_name].min_addr + relative_addr
                except KeyError as e:
                    print("self.proj.loader.shared_objects = {}".format(self.proj.loader.shared_objects))
                    raise e
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

    def get_node_condition(self, node, jumps_on_branch):
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
                        print("[!] Unhandled function call '{:#x}: call {}'".format(insn.address, func_name))
                        continue

                    res.append(ir.Assign(call_f.ret, call_f))
                    res.append(ir.Eq(r_ret, call_f.ret))
            return res

        def __jump_not_taken_constraint(insns, object_file, jumps_on_branch):
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

                ### Funtion slector
                def MUX(f1, f2):
                    return {True: f1, False: f2}[jumps_on_branch]

                ### Conditional Branch
                ### TODO: check if implemented correctlly
                for insn in [jcc_insn]:
                    if compare_insn.id in [capstone.x86.X86_INS_CMP]:
                        # NOTE: Returns constraint of jump taken or jump *not* taken
                        if insn.id == capstone.x86.X86_INS_JNE: # jnz
                            return MUX(ir.Ne, ir.Eq)(left, right)
                        if insn.id == capstone.x86.X86_INS_JE:  # jz
                            return MUX(ir.Eq, ir.Ne)(left, right)
                        if insn.id == capstone.x86.X86_INS_JA:  # left > right
                            return MUX(ir.Gt, ir.Le)(left, right)
                        if insn.id == capstone.x86.X86_INS_JA:  # left >= right
                            return MUX(ir.Ge, ir.Lt)(left, right)
                        if insn.id == capstone.x86.X86_INS_JB:  # left < right
                            return MUX(ir.Le, ir.Gt)(left, right)
                        if insn.id == capstone.x86.X86_INS_JBE:  # left <= right
                            return MUX(ir.Le, ir.Gt)(left, right)
                        if insn.id == capstone.x86.X86_INS_JL:  # left < right
                            return MUX(ir.Lt, ir.Ge)(left, right)
                        if insn.id == capstone.x86.X86_INS_JLE:  # left <= right
                            return MUX(ir.Le, ir.Gt)(left, right)
                    elif compare_insn.id in [capstone.x86.X86_INS_TEST]:
                        if left == right:
                            if insn.id == capstone.x86.X86_INS_JNE: # jnz
                                return MUX(ir.Ne, ir.Eq)(left, ir.Value(0))
                            if insn.id == capstone.x86.X86_INS_JE:  # jz
                                return MUX(ir.Eq, ir.Ne)(left, ir.Value(0))
                        else:
                            if insn.id == capstone.x86.X86_INS_JNE: # jnz
                                return MUX(ir.Ne, ir.Eq)(ir.Band(left, right), ir.Value(0))
                            if insn.id == capstone.x86.X86_INS_JE:  # jz
                                return MUX(ir.Eq, ir.Ne)(ir.Band(left, right), ir.Value(0))
                    raise UnhandledCaseError("Unsupported instruction '{:#x}: {} {}'".format(insn.address, insn.mnemonic, insn.op_str))

        if self.debug: print("[*] get_node_condition: visited node {} (addr={:#x})".format(node, node.addr))

        assert isinstance(jumps_on_branch, bool)

        object_file = self.find_object_containing(rebased_addr=node.addr)
        insns = self.get_cfg_node_insns_at(rebased_addr=node.addr)
        assert len(insns) > 0

        # assign_constraint = __assign_constraint(insns, object_file)
        assign_constraint = ir.ConstraintList()
        call_constraint = __call_function(self, insns, object_file)
        jump_not_taken_constraint = __jump_not_taken_constraint(insns, object_file, jumps_on_branch=jumps_on_branch)
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
        # import ipdb; ipdb.set_trace()
        if node.predecessors[0].is_simprocedure: # call instrcution (incorrect implementation)
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