import os, sys
import functools

from engine import *
from nao.util import strip_null, X, Program, Tactic
from nao.encoder import encode_constraint_to_loss_function_ast

def xadapter(v):
    try:
        s = ''.join(map(lambda _: chr(round(_)) if _ > 0 else '\x00', v.list()))
        s = strip_null(s)
        return X(args=[s]) # sage var -> program input
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> v = {}".format(x))
        exit(1)

def yadapter(variables, y):
    try:
        res = []
        for v in variables:
            try:
                res.append(y[v.name])
            except KeyError:
                ### FIXME: this is not internal variable value. Program does not reached the block.
                if False: print("[!] Value of v not found. assume 0: v = {}".format(v))
                res.append(0)
        return res
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> y = {}".format(y))
        exit(1)

def main(main_file):
    print()
    print("[*] main")

    p = Program(main_file, xadapter, yadapter)

    ### Generate constraints on y
    # find_addr = 0x7e1
    find_addr = 0x7da
    constraints = p.get_constraints(Tactic.near_path_constraint, relative_addr=find_addr)
    print("y constraints = {}".format(constraints))
    
    ### Define function N
    N = p.N(constraints)

    ### Define loss function
    L = p.L(constraints)

    ### Solve constraints
    ### TODO: auto set initial x 
    model = NeuSolv(N, L, zero_vector(8))

    print("=" * 8)
    if model:
        print("[*] found")
        print("y constraints = {}".format(constraints))
        print("model: {}".format(model))
        print("-> {!r}".format(xadapter(model)))
    else:
        print("[*] not found")

    print("-" * 8)
    print("Lap Time: {}".format(stat.lap_time))

if __name__ == "__main__":
    main_file = "sample/simple-if-statement-tree"
    main(main_file)