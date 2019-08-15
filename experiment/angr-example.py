#!/usr/bin/python
import angr
import angrutils
import capstone

addr = lambda symbol: proj.loader.find_symbol(symbol).relative_addr

def to_hex_list(l):
    return list(map(lambda x: hex(x), l))

### Load binary
proj = angr.Project('sample/simple-if-statement-tree', load_options={'auto_load_libs': False})

### Generate a static CFG
cfg = proj.analyses.CFGFast()

### Get a node
main_addr = proj.loader.find_symbol('main').rebased_addr
node = cfg.get_any_node(main_addr + 0xad, anyaddr=True)
assert node is not None
print("node = {}".format(node))

### Print infomation of the node
# print(dir(node))
print("node.addr = {:#x}".format(node.addr))
print("node.predecessors = {}".format(node.predecessors))
print("node.successors = {}".format(node.successors))
# print("node.irsb: {}".format(node.irsb))
print("node.block.pp: ".format())
node.block.pp()
print("node.block.capstone.insns = {}".format(list(node.block.capstone.insns)))
exit(1)

print("node.byte_string = {}".format(to_hex_list(node.byte_string)))

angrutils.plot_cfg(cfg, "simple-if-statement-tree-cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
for insn in md.disasm(node.byte_string, node.instruction_addrs[0] - proj.loader.main_object.min_addr):
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