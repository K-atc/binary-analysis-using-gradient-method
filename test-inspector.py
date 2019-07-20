#!/usr/bin/python
from nao.util import Tactic
from nao.inspector import Inspector
from nao.ast import constraint as ir

def test_if_statement_tree():
    print("\n[*] === simple-if-statement-tree ===")
    inspector = Inspector("sample/simple-if-statement-tree", debug=True)
    cmp1 = 0x7d6

    cond = inspector.get_condition_at(Tactic.near_path_constraint, relative_addr=cmp1)
    print("condition = {}".format(cond))
    variables = cond.get_variables()
    print("variables = {} (type={})".format(variables, type(variables)))

    inspector.run(args=["#aab"])
    return inspector.collect(cond)

def test_elf_cheker(stdin):
    print("\n[*] === simple-elf-checker (stdin={}) ===".format(stdin))
    inspector = Inspector("sample/simple-elf-checker", debug=True)
    find_addr = 0x836

    cond = inspector.get_condition_at(Tactic.near_path_constraint, relative_addr=find_addr)
    print("constraints = {}".format(cond))
    variables = cond.get_variables()
    print("variables = {} (type={})".format(variables, type(variables)))

    inspector.run(stdin=stdin)
    return inspector.collect(cond)

def test_if_statement_tree_with_assume(stdin=""):
    print("\n[*] === simple-elf-checker with Assume ===".format())
    inspector = Inspector("sample/simple-if-statement-tree", debug=True)
    find_addr = 0x7d6 # if (len() == 3)
    # find_addr = 0x7e1 # call <correct>

    cond = inspector.get_condition_at(Tactic.near_path_constraint, relative_addr=find_addr)
    print("condition = {}".format(cond))

    inspector.run(args=["AAAA"])
    return inspector.collect(ir.ConstraintList([ir.Assume(cond[0]), cond]))

if __name__ == "__main__":
    res = test_if_statement_tree()
    print(res)
    assert len(res) > 0

    res = test_elf_cheker(stdin=b"\x7fELF") # satisfies all constraints
    print(res)
    assert len(res) > 0

    res = test_elf_cheker(stdin=b"abcd")
    print(res)
    assert len(res) > 0

    res = test_if_statement_tree_with_assume(stdin=b"abcd")
    print(res)
    assert len(res) > 0