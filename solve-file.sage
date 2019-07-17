import os, sys
import struct
import numbers
from pprint import pformat
import ctypes
import numpy as np

from engine import NeuSolv, stat
from nao.util import strip_null, Tactic
from nao.program import Program, X

magic = False
checksum = True

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
        # print("\ts = {!r}".format(s))
        
        ### FIXME: arg[0] should use fs.path('sample.tar')
        return X(args=['./fs-Inspector/test.tar'], files={'test.tar': content}, env={'LD_LIBRARY_PATH': '/vagrant/sample/'}) # sage var -> program input
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
    return vector(res)

### REFACTER: No need to implement yadapter in solver
def yadapter(constraint, y):
    try:
        variables = constraint.get_variables()
        # print("[*] y = {}".format(y))
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
                elif len(value) == 1:
                    res.append(ord(value))
            except KeyError:
                ### FIXME: this is not internal variable value. Program does not reached the block.
                if True: print("[!] yadapter(): Value of {} not found: {}".format(v.name, v))
                exit(1)
        return res
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print()
        print("-> value = {!r}".format(value))
        print("-> y = {}".format(y))
        import ipdb; ipdb.set_trace()
        exit(1)

def main():
    ### Export Environment Variable
    os.environ['LD_LIBRARY_PATH'] = '/vagrant/sample/'

    ### Load analysis target
    p = Program("./sample/file", xadapter, yadapter, debug=False)

    ### Generate post condition y
    name_libmagic_so = 'libmagic.so.1'
    # find_addr = 0x17279 # if ((ms->flags & (MAGIC_APPLE|MAGIC_EXTENSION)) != 0) -> else
    # find_addr = 0x0173F8 # return 3 at is_tar
    find_addr = 0x173D6 # reach strcmp(s1, "ustar  \x00")
    constraints = p.get_constraints(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=find_addr)
    print("[*] constraints = {}".format(pformat(constraints)))
    print("[*] variables = {}".format(pformat(constraints.get_variables())))

    ### Define function N
    N = p.N(constraints)

    ### Define loss function
    L = p.L(constraints)

    ### Solve constraints
    ### TODO: auto set initial x 
    if magic:
        model = NeuSolv(N, L, vector([ord(x) for x in "ustar  \x00"]), xadapter)
        # model = NeuSolv(N, L, vector([ord(x) for x in "ustar**\x00"]), xadapter)
    if checksum:
        model = NeuSolv(N, L, vector([1221]), xadapter)
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
    print("Measured epics time:")
    print("\tmean   = {} sec".format(np.mean(stat.lap_time)))
    print("\tmedian = {} sec".format(np.median(stat.lap_time)))
    print("\tstd.   = {} sec".format(np.std(stat.lap_time)))

if __name__ == "__main__":
    main()