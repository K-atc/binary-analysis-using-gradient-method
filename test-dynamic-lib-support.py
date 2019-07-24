#!/usr/bin/python
import os
from nao.util import Tactic
from nao.inspector import Inspector

def test_file():
    print("\n[*] === file ===")
    name_libmagic_so = 'libmagic.so.1'
    inspector = Inspector("./sample/file", debug=True)
    # find_addr = 0x1742D # ret block of is_tar
    find_addr = 0x173F8 # return 3 at is_tar
    # find_addr = 0x17293

    cond = inspector.get_condition_at(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=find_addr)
    print("post condition = {}".format(cond))

    inspector.run(args=["./sample.tar"], env={'LD_LIBRARY_PATH': os.environ['LD_LIBRARY_PATH']})
    return inspector.collect(cond)

if __name__ == "__main__":
    res = test_file()
    print(res)
    assert len(res) > 0
