import os, sys
import struct
from pprint import pformat
import numpy as np
import argparse

from nao.engine import NeuSolv, stat
from nao.fs import FileSystem
from nao.util import get_addr_from_env, strip_null, round_real_to_char, round_real_to_uint, vectorize
from nao.tactics import Tactic
from nao.program import Program, X
from nao.ast import constraint as ir
from nao.exceptions import UnhandledCaseError

parser = argparse.ArgumentParser()
parser.add_argument('--magic', dest='magic', action='store_true')
parser.add_argument('--checksum', dest='checksum', action='store_true')
parser.add_argument('--init', dest='init')

args = parser.parse_args()
magic, checksum = args.magic, args.checksum
assert magic or checksum, "usage: provide --magic or --checksum"

with open('sample.tar') as f:
    tar_file = f.read()

def xadapter(v):
    try:
        if magic:
            assert len(v) == 8
            s = ''.join(map(lambda _: round_real_to_char(_), v.list()))
            assert len(s) >= 8
            content = tar_file[:0x101] + s + tar_file[0x101 + len(s):] # for magic
        if checksum:
            assert len(v) == 1
            s = "{:06o}\0 ".format(round_real_to_uint(v[0]))
            # s = ''.join(map(lambda _: '01234567'[round_real_to_uint(_) % 8], v.list()))
            assert len(s) == 8
            content = tar_file[:0x94] + s + tar_file[0x94 + len(s):] # for checksum
        
        if magic:
            print("\ts = {!r}".format(s))

        fs = FileSystem('./fs-file/')
        fs.create('test.tar', content)
        return X(args=[fs.path('test.tar')], files=fs, env={'LD_LIBRARY_PATH': os.environ['LD_LIBRARY_PATH']}) # sage var -> program input
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print()
        print("-> v = {}".format(v))
        import ipdb; ipdb.set_trace()
        exit(1)

def main():
    ### Load analysis target[]
    p = Program("./sample/file", xadapter, debug=False)

    ### Generate post condition y
    name_libmagic_so = 'libmagic.so.1'
    addr_check_checksum_passed = get_addr_from_env('ADDR_CHECKSUM_PASSED') # 0x173D6 # mov    rax,QWORD PTR [rbp-0x10]
    if checksum:
        find_addr = addr_check_checksum_passed
    if magic:
        find_addr = get_addr_from_env('ADDR_RET_3') # 0x173F8 # return 3 at is_tar
    call_is_tar_constraints = p.get_constraints(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=addr_check_checksum_passed)[0]
    assume_checksum = ir.ConstraintList([ir.Assume(call_is_tar_constraints)])
    constraints = p.get_constraints(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=find_addr)
    constraints += assume_checksum
    print("[*] constraints = {}".format(pformat(constraints)))
    print("[*] variables = {}".format(pformat(constraints.get_variables())))

    ### Define function N
    N = p.N(constraints)

    ### Define loss function
    L = p.L(constraints)

    ### Solve constraints
    ### TODO: auto set initial x 
    if magic:
        if args.init:
            print("[*] args.init = {!r}".format(args.init))
            x0 = vector([ord(x) for x in args.init])
        else:
            # model = NeuSolv(N, L, vector([ord(x) for x in "ustar**\x00"]), xadapter)
            # model = NeuSolv(N, L, vector([ord(x) for x in "USTAR**Z"]), xadapter)
            x0 = vector([ord(x) for x in "ustar**\x00"])
        print("[*] x0 = {}".format(x0))
        model = NeuSolv(N, L, x0, xadapter)
    if checksum:
        model = NeuSolv(N, L, vector([4650]), xadapter)
        # model = NeuSolv(N, L, zero_vector(8), xadapter)

    print("=" * 8)
    if model is not None:
        print("[*] found")
        print("y constraints = {}".format(constraints))
        print("model: {}".format(model))
        print("-> {!r}".format(xadapter(model)))

        stdout, stderr = p.run(xadapter(model))
        print("[*] stdout:")
        print(stdout)
        print("[*] stderr:")
        print(stderr)
    else:
        print("[*] not found")

    print("-" * 8)
    if stat.lap_time:
        print("Number of epics: {}".format(len(stat.lap_time)))
        print("Measured epics time:")
        print("\tmean   = {} sec".format(np.mean(stat.lap_time)))
        print("\tmedian = {} sec".format(np.median(stat.lap_time)))
        print("\tstd.   = {} sec".format(np.std(stat.lap_time)))

    print("-" * 8 + "\n")
    return (model is not None)

if __name__ == "__main__":
    found = main()
    ### Tell CI of result
    if found: 
        print("[*] OK")
        exit(0)
    else:
        print("[!] NG")
        exit(1)