#!/usr/bin/python
import angr
import angrutils
import capstone

addr = lambda symbol: proj.loader.find_symbol(symbol).relative_addr

def to_hex_list(l):
    return list(map(lambda x: hex(x), l))

proj = angr.Project('sample/simple-if-statement-tree', load_options={'auto_load_libs': False})

# Generate a static CFG
cfg = proj.analyses.CFGFast()

print("entry = {:#x}".format(proj.entry))

print("graph:")
print(cfg.graph)

main_node = cfg.get_any_node(proj.loader.find_symbol('main').rebased_addr + (0x7d6 - 0x72d))
print(main_node)

print("main = {:#x}".format(addr('main')))

print(dir(main_node))
print("node.irsb = {}".format(main_node.irsb))
print("node.addr = {:#x}".format(main_node.addr))
print("node.predecessors = {}".format(main_node.predecessors))
print("node.instruction_addrs = {}".format(to_hex_list(main_node.instruction_addrs)))
print("node.byte_string = {}".format(to_hex_list(main_node.byte_string)))
# print("node.to_codenode() = {}".format(main_node.to_codenode()))
print("node.successors = {}".format(main_node.successors))

angrutils.plot_cfg(cfg, "simple-if-statement-tree-cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
for insn in md.disasm(main_node.byte_string, main_node.instruction_addrs[0] - proj.loader.main_object.min_addr):
    print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
    # print("dir(insn) = {}".format(dir(insn)))
    print("insn.id = {}".format(insn.id))
    print("insn.insn_name() = {}".format(insn.insn_name()))
    if insn.id == capstone.x86.X86_INS_CMP:
        print("cmp")
    if insn.id == capstone.x86.X86_INS_JNE:
        print("jne")
    for c, op in enumerate(insn.operands):
        if op.type == capstone.x86.X86_OP_REG:
            print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(op.reg)))
        if op.type == capstone.x86.X86_OP_IMM:
            print("\t\toperands[%u].type: IMM = %#x" % (c, op.imm))
        if op.type == capstone.x86.X86_OP_MEM:
            print("dir(op.mem) = {}".format(dir(op.mem)))
            print("\t\toperands[%u].type: MEM" % c)
            print("op.size = {}".format(op.size))
            if op.mem.segment != 0:
                print("\t\t\toperands[%u].mem.segment: REG = %s" % (c, insn.reg_name(op.mem.segment)))
            if op.mem.base != 0:
                print("\t\t\toperands[%u].mem.base: REG = %s" % (c, insn.reg_name(op.mem.base)))
            if op.mem.index != 0:
                print("\t\t\toperands[%u].mem.index: REG = %s" % (c, insn.reg_name(op.mem.index)))
            if op.mem.scale != 1:
                print("\t\t\toperands[%u].mem.scale: %u" % (c, op.mem.scale))
            if op.mem.disp != 0:
                print("\t\t\toperands[%u].mem.disp: %#x" % (c, op.mem.disp))


"""
'address', 'bytes', 'errno', 'group', 'group_name', 'groups', 'id', 'insn_name', 'mnemonic', 'op_count', 'op_find', 'op_str', 'reg_name', 'reg_read', 'reg_write', 'regs_access', 'regs_read', 'regs_write', 'size']
'access', 'avx_bcast', 'avx_zero_opmask', 'imm', 'mem', 'reg', 'size', 'type', 'value']
"""