#!/usr/bin/python
from util import *

def test_if_statement_tree():
    print("\n[*] === simple-if-statement-tree ===")
    inspector = Inspector("sample/simple-if-statement-tree")
    cmp1 = 0x7d6

    cond = inspector.get_condition_at(Tactic.near_path_constraint, relative_addr=cmp1)
    print("condition = {}".format(cond))
    variables = cond.get_variables()
    print("variables = {} (type={})".format(variables, type(variables)))

    breakpoint_addrs = set(map(lambda _: _.addr, variables))

    inspector.run(["#aab"])
    for addr in breakpoint_addrs:
        inspector.set_breakpoint(relative_addr=addr)
        inspector.cont()
        res = inspector.read_vars(variables.find(addr=addr))
        print("read_var() = {}".format(res))

def test_elf_cheker():
    print("\n[*] === simple-elf-checker ===")
    inspector = Inspector("sample/simple-elf-checker")
    find_addr = 0x836

    # print("main node = {}".format(inspector.get_cfg_node_at(rebased_addr=inspector.find_symbol('main').rebased_addr)))
    # print("main node = {}".format(inspector.get_cfg_node_at(relative_addr=0x77a)))

    cond = inspector.get_condition_at(Tactic.near_path_constraint, relative_addr=find_addr)
    print("condition = {}".format(cond))

if __name__ == "__main__":
    test_if_statement_tree()
    test_elf_cheker()