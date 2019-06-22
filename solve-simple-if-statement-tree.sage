import os, sys
import functools

from engine import *
from util import *

def xadapter(v):
    try:
        s = ''.join(map(lambda _: chr(_) if _ > 0 else '\x00', v.list()))
        s = strip_null(s)
        return X(args=[s]) # sage var -> program input
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> v = {}".format(x))
        exit(1)

def yadapter(variables, y):
    try:
        res = []
        for v in variables:
            res.append(y[v.name])
        return res
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> y = {}".format(y))
        exit(1)

def test(N):
    print()
    print("[*] test")
    x = X(args=['aaa'])
    vy = p.call(x)
    print("vectored y = {}".format(vy))

def main(N):
    print()
    print("[*] main")

    ### Define loss function
    ### TODO: Automate generation of L
    var('x_0 x_len')
    L(x_0, x_len) = L_a_eq_b(x_0, ord('#')) + L_a_eq_b(x_len, 3)

    ### Solve constraints
    ### TODO: auto set initial x 
    model = NeuSolv(N, L, zero_vector(8))

    print("=" * 8)
    if model:
        print("[*] found")
        print("model: {}".format(model))
        # print("-> {!r}".format(vector_to_string(model)))
        print("-> {!r}".format(xadapter(model)))
    else:
        print("[*] not found")

    print("-" * 8)
    print("Lap Time: {}".format(stat.lap_time))

if __name__ == "__main__":
    main_file = "sample/simple-if-statement-tree"

    ### Define function N
    p = Program('sample/simple-if-statement-tree', xadapter, yadapter)
    N = p.call_with_adapter

    ### Provide y variables in constraints
    cmp1 = 0x7d6
    cons = p.get_constraints(Tactic.near_path_constraint, relative_addr=cmp1)
    print("y constrints = {}".format(cons))
    p.set_y_constraints(cons)

    test(N)
    main(N)