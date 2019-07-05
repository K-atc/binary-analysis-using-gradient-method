#!/usr/bin/python
from nao.util import Inspector, Tactic
import signal

def test_file():
    print("\n[*] === file ===")
    name_libmagic_so = 'libmagic.so.1'
    inspector = Inspector("/usr/local/bin/file", debug=True)
    find_addr = 0x133c4

    cond = inspector.get_condition_at(Tactic.near_path_constraint, object_name=name_libmagic_so,relative_addr=find_addr)
    print("condition = {}".format(cond))
    y_variables = cond.get_variables()
    print("y_variables = {} (type={})".format(y_variables, type(y_variables)))

    breakpoint_addrs = sorted(set(map(lambda _: _.addr, y_variables)))

    # inspector.run(args=["./nao/fs-Inspector/stdin"], stdin=b"aaaaa")
    inspector.run(args=["/vagrant/sample.tar"])

    y = {}
    for addr in breakpoint_addrs:
        b = inspector.set_breakpoint(object_name=name_libmagic_so, relative_addr=addr)
    while True:
        try:
            inspector.cont()
        except Exception as e:
            # print(e)
            break
        if not inspector.is_tracee_attached():
            break
        pc = inspector.process.getInstrPointer()
        addr = inspector.get_relative_addr(object_name=name_libmagic_so, tracee_rebased_addr=pc - 1)
        res = inspector.read_vars(y_variables.find(addr=addr))
        y.update(res)
        b = inspector.process.findBreakpoint(pc - 1)
        if b:
            print("[*] remove breakpoint at {:#x}".format(b.address))
            b.desinstall(set_ip=True)
        ### Reinstall breakpoint
        inspector.process.singleStep()
        # inspector.cont()
        inspector.process.waitSignals(signal.SIGTRAP)
        inspector.set_breakpoint(object_name=name_libmagic_so, relative_addr=addr)


    inspector.stop()
    print("y = {}".format(y))
    return y

if __name__ == "__main__":
    res = test_file()
    print(res)
    assert len(res) > 0
