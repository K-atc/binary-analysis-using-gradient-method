import ptrace.debugger
import signal
import angr
import capstone
import subprocess
import struct
import ir

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

class UnhandledCaseError(Exception):
    pass

class InvalidAddressError(Exception):
    pass

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

        ### angr setup
        self.proj = angr.Project(self.main_file, load_options={'auto_load_libs': False})
        self.cfg = self.proj.analyses.CFGFast()

    def __del__(self):
        if self.pid > 0:
            if self.debug: print("[*] Detaching process (pid={})".format(self.pid))
            self.process.detach()
            self.debugger.quit()

    def get_tracee_tracee_main_object_base_addr(self):
        mmap = self.process.readMappings()
        for x in mmap:
            if x.pathname and self.main_file in str(x.pathname):
                if self.debug: print("{:#x} {}".format(x.start, x.pathname))
                return x.start
        raise UnhandledCaseError("get_main_base_addr: Cannot find main object base address")

    def set_breakpoint(self, relative_addr=None, rebased_addr=None):
        if relative_addr:
            self.breakpoints.append(self.process.createBreakpoint(self.tracee_main_object_base_addr + relative_addr))
            return True
        if rebased_addr:
            self.breakpoints.append(self.process.createBreakpoint(rebased_addr))
            return True
        raise UnhandledCaseError("set_breakpoint: provide rebased_addr or relative_addr")

    def run(self, args=[]):
        assert(isinstance(args, list))
        args = [self.main_file] + args
        self.args = args
        self.breakpoints = []

        ### ptrace setup
        tracee = subprocess.Popen(args)
        self.pid = tracee.pid
        self.debugger = ptrace.debugger.PtraceDebugger()
        if self.debug: print("[*] Attach the running process %s" % tracee.pid)
        self.process = self.debugger.addProcess(self.pid, False)
        self.tracee_main_object_base_addr = self.get_tracee_tracee_main_object_base_addr()

    def cont(self):
        if self.pid > 0:
            self.process.cont()
            self.process.waitSignals(signal.SIGINT, signal.SIGTRAP, signal.SIGSEGV)
            if self.debug: print("[*] handled signal")
        else:
            print("[!] proess is not running")
            return False

    ### TODO: Terminate process
    def stop(self):
        pass

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
        assert(isinstance(addr, int))
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
                        v.append(ir.Variable(var(insn, op), op.size))
                    if op.type == capstone.x86.X86_OP_IMM:
                        v.append(ir.Value(op.imm))
                    if op.type == capstone.x86.X86_OP_MEM:
                        v.append(ir.Variable(var(insn, op), op.size))
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

    def read_vars(self, start_addr, code, reg, mem, debug=True):
        res = {}
        for insn in md.disasm(code, start_addr):
            print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
            for c, op in enumerate(insn.operands):
                if op.type == capstone.x86.X86_OP_REG:
                    print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(op.reg)))
                    res[var(insn, op)] = reg(op.reg)
                if op.type == capstone.x86.X86_OP_MEM:
                    print("\t\toperands[%u].type: MEM" % c)
                    if debug: print("[*] {} = {:#x}".format(insn.reg_name(op.mem.base), reg(insn.reg_name(op.mem.base))))
                    mem_read_addr = reg(insn.reg_name(op.mem.base)) + op.mem.disp
                    if op.mem.index != 0:
                        mem_read_addr += reg(insn.reg_name(op.mem.index)) * op.mem.scale
                    res[var(insn, op)] = bytes_to_uint(mem(mem_read_addr, op.size), op.size)
        return res

    def read_vars_at(self, relative_addr=None, rebased_addr=None):
        if relative_addr:
            return self.read_vars(relative_addr, self.get_cfg_node_code_at(relative_addr=relative_addr), self.process.getreg, self.process.readBytes, self.debug)
        if rebased_addr:
            return self.read_vars(rebased_addr, self.get_cfg_node_code_at(rebased_addr=rebased_addr), self.process.getreg, self.process.readBytes, self.debug)
        raise UnhandledCaseError("read_vars_at: provide rebased_addr or relative_addr")


class Tactic:
    @staticmethod
    def near_path_constraint(inspector, node):
        predecessors_conditions = []
        for predecessor in node.predecessors:
            predecessor_condition = inspector.get_node_condition(predecessor)
            if predecessor_condition != ir.Top():
                predecessors_conditions.append(predecessor_condition)
        node_constraint = inspector.get_node_condition(node)
        if node_constraint == ir.Top():
            return predecessors_conditions        
        else:
            return predecessors_conditions + [node_constraint]