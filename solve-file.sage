import os, sys
import struct
import numbers

from engine import NeuSolv, stat
from nao.util import strip_null, Tactic
from nao.program import Program, X
# from nao.ast import constraint as C

def xadapter(v):
    def round_real_to_char(i):
        if i < 0:
            return '\x00'
        else:
            i = round(i)
            return strip_null(struct.pack('<Q', i))

    try:
        s = ''.join(map(lambda _: round_real_to_char(_), v.list()))
        s = strip_null(s)
        ### FIXME: arg[0] use fs.path('sample.tar')
        return X(args=['./fs-Inspector/sample.tar'], files={'sample.tar': open('sample.tar').read()}, env={'LD_LIBRARY_PATH': '/vagrant/sample/'}) # sage var -> program input
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> v = {}".format(v))
        exit(1)

def vectorize(a):
    res = []
    for v in list(a):
        res.append(ord(v))
    return vector(res)

def yadapter(variables, y):
    try:
        print("[*] y = {}".format(y))
        res = []
        for v in variables:
            try:
                value = y[v.name]
                if isinstance(value, numbers.Number): # Scalar
                    res.append(value)
                elif len(value) == 1:
                    res.append(ord(value))
                else: # Vector
                    if value == "###DO#NOT#USE###": # FIXME: Dirty
                        continue
                    # res.append(vectorize(value))
                    continue
            except KeyError:
                ### FIXME: this is not internal variable value. Program does not reached the block.
                if True: print("[!] yadapter(): Value of {} not found: {}".format(v.name, v))
                exit(1)
        return res
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> value = {!r}".format(value))
        print("-> y = {}".format(y))
        import ipdb; ipdb.set_trace()
        exit(1)

def main():
    ### Load analysis target
    p = Program("./sample/file", xadapter, yadapter, debug=True)

    ### Generate post condition y
    name_libmagic_so = 'libmagic.so.1'
    find_addr = 0x173F8 # return 3 at is_tar
    constraints = p.get_constraints(Tactic.near_path_constraint, object_name=name_libmagic_so, relative_addr=find_addr)
    print("constraints = {}".format(constraints))

    ### Define function N
    N = p.N(constraints)

    ### Define loss function
    L = p.L(constraints)

    ### Solve constraints
    ### TODO: auto set initial x 
    model = NeuSolv(N, L, zero_vector(18), xadapter)

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
    print("Lap Time: {}".format(stat.lap_time))

if __name__ == "__main__":
    main()