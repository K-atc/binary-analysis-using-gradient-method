#!/usr/bin/python
from nao.util import Inspector, Tactic
import signal

def test_file():
    print("\n[*] === file ===")
    name_libmagic_so = 'libmagic.so.1'
    inspector = Inspector("/usr/local/bin/file", debug=True)
    find_addr = 0x133c4

    cond = inspector.get_condition_at(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=find_addr)
    print("post condition = {}".format(cond))
    y_variables = cond.get_variables()
    print("y_variables = {} (type={})".format(y_variables, type(y_variables)))

    inspector.run(args=["/vagrant/sample.tar"])

    y = {}
    for v in y_variables:
        # b = inspector.set_breakpoint(variable=v)
        print(v)
        b = inspector.set_breakpoint(object_name=name_libmagic_so, relative_addr=v.addr)
    while True:
        try:
            inspector.cont()
        except Exception as e:
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
            print("[*] remove breakpoint at {:#x}".format(b.address))
            b.desinstall(set_ip=True)
        ### Reinstall breakpoint
        inspector.process.singleStep()
        inspector.process.waitSignals(signal.SIGTRAP)
        inspector.set_breakpoint(rebased_addr=breakpoint_addr)

    inspector.stop()
    print("y = {}".format(y))
    return y

if __name__ == "__main__":
    res = test_file()
    print(res)
    assert len(res) > 0
