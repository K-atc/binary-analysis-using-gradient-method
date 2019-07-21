import os, sys
import struct
import numbers
from pprint import pformat
import ctypes
import numpy as np
import argparse

from engine import NeuSolv, stat
from nao.fs import FileSystem
from nao.util import strip_null, Tactic
from nao.program import Program, X
from nao.ast import constraint as ir
from nao.exceptions import UnhandledCaseError

parser = argparse.ArgumentParser()
parser.add_argument('--magic', dest='magic', action='store_true')
parser.add_argument('--checksum', dest='checksum', action='store_true')

args = parser.parse_args()
magic, checksum = args.magic, args.checksum
assert magic or checksum

with open('sample.tar') as f:
    tar_file = f.read()

def xadapter(v):
    def round_real_to_uint(i):
        return int(abs(round(i)))

    def round_real_to_char(i):
        i = round_real_to_uint(i)
        if i < (1 << 8):
            return struct.pack('<B', i)
        if i < (1 << 16):
            return struct.pack('<H', i)
        if i < (1 << 32):
            return struct.pack('<I', i)
        if i < (1 << 64):
            return struct.pack('<Q', i)

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

        ### FIXME: arg[0] should use fs.path('sample.tar')
        fs = FileSystem('./fs-file/')
        fs.create('test.tar', content)
        return X(args=[fs.path('test.tar')], files=fs, env={'LD_LIBRARY_PATH': '/vagrant/sample/'}) # sage var -> program input
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print()
        print("-> v = {}".format(v))
        import ipdb; ipdb.set_trace()
        exit(1)

def vectorize(a):
    res = []
    for v in list(a):
        res.append(ord(v))
    return vector(res) # pylint: disable=E0602

### REFACTER: No need to implement yadapter in solver
def yadapter(constraint, y):
    try:
        variables = constraint.get_variables()
        res = []
        for v in variables:
            try:
                value = y[v.name]
                if isinstance(value, numbers.Number): # Scalar
                    if value < 0x100000000: # 32bit int
                        value = ctypes.c_int(value).value                    
                    else: # 64bit int
                        value = ctypes.c_long(value).value
                    res.append(value)
                elif len(value) == 1: # array-like object
                    res.append(ord(value))
                else: # sage.symbolic.expression.Expression ?
                    res.append(value)
                    # raise UnhandledCaseError("v={}".format(v))
            except KeyError:
                ### NOTE: Program does not reached the block.
                if True: print("[!] yadapter(): Value of {} not found: {}".format(v.name, v))
                exit(1)
        assert len(res) == len(variables)
        return res
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("")
        print("-> value = {!r}".format(value))
        print("-> y = {}".format(y))
        print("-> variables = {}".format(variables))
        import ipdb; ipdb.set_trace()
        exit(1)

def main():
    ### Export Environment Variable
    os.environ['LD_LIBRARY_PATH'] = '/vagrant/sample/'

    ### Load analysis target
    p = Program("./sample/file", xadapter, yadapter, debug=False)

    ### Generate post condition y
    name_libmagic_so = 'libmagic.so.1'
    addr_call_is_tar = 0x173D6
    if checksum:
        find_addr = 0x173D6 # strcmp(s1, "ustar  \x00")
    if magic:
        find_addr = 0x173F8 # return 3 at is_tar
    call_is_tar_constraints = p.get_constraints(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=addr_call_is_tar)[0]
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
        # model = NeuSolv(N, L, vector([ord(x) for x in "ustar  \x00"]), xadapter)
        model = NeuSolv(N, L, vector([ord(x) for x in "USTAR**\x00"]), xadapter)
        # model = NeuSolv(N, L, vector([ord(x) for x in "USTAR**Z"]), xadapter)
    if checksum:
        model = NeuSolv(N, L, vector([1000]), xadapter)
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
        print("Measured epics time:")
        print("\tmean   = {} sec".format(np.mean(stat.lap_time)))
        print("\tmedian = {} sec".format(np.median(stat.lap_time)))
        print("\tstd.   = {} sec".format(np.std(stat.lap_time)))

    print("-" * 8 + "\n")

if __name__ == "__main__":
    main()