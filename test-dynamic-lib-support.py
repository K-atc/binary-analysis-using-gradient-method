#!/usr/bin/python
from nao.util import Inspector, Tactic
import signal

def test_file():
    print("\n[*] === file ===")
    name_libmagic_so = 'libmagic.so.1'
    inspector = Inspector("./sample/file", debug=True)
    find_addr = 0x173f8

    cond = inspector.get_condition_at(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=find_addr)
    print("post condition = {}".format(cond))
    y_variables = cond.get_variables()
    print("y_variables = {} (type={})".format(y_variables, type(y_variables)))

    inspector.run(args=["/vagrant/sample.tar"])

    return inspector.collect(y_variables)

if __name__ == "__main__":
    res = test_file()
    print(res)
    assert len(res) > 0
