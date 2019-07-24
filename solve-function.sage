import ctypes

from engine import *
from nao.util import strip_null, X, Program, Tactic, FixedValue
from nao.encoder import encode_constraint_to_loss_function_ast
from nao.ast import constraint as C

def xadapter(v):
    try:
        x = "3.00"
        a = "{}".format(v[0])
        b = "{}".format(v[1])
        c = "{}".format(v[2])
        return X(args=[x, a, b, c]) # sage var -> program input
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> v = {}".format(v))
        exit(1)

def yadapter(variables, y):
    try:
        res = []
        for v in variables:
            try:
                res.append(ctypes.c_long(y[v.name]).value)
            except KeyError:
                ### FIXME: this is not internal variable value. Program does not reached the block.
                if False: print("[!] Value of v not found. assume 0: v = {}".format(v))
                res.append(0xff)
        return res
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> y = {}".format(y))
        exit(1)

def main():
    ### Load analysis target
    main_file = "sample/function"
    # p = Program(main_file, xadapter, yadapter, debug=True)
    p = Program(main_file, xadapter, yadapter)
    """
 89b:	e8 2a fe ff ff       	call   6ca <f>
 8a0:	48 85 c0             	test   rax,rax
    """

    ### Generate constraints on y
    """
vagrant@ubuntu-18:/vagrant$ ./sample/function 3.0 10.0 5.0 3.0
f(x) = 108.000000[]
    """
    # find_addr = 0x400602
    constraints = C.ConstraintList()
    constraints.append(C.Eq(C.Variable('y', 8, 0x8a0, C.Register('rax')), C.Value(108)))
    print("y constraints = {}".format(constraints))
    # exit(1)

    ### Define function N
    N = p.N(constraints)

    ### Define loss function
    L = p.L(constraints)

    ### Solve constraints
    ### TODO: auto set initial x 
    # model = NeuSolv(N, L, zero_vector(3), xadapter)
    model = NeuSolv(N, L, vector([50, 0, 0]), xadapter)
    # model = NeuSolv(N, L, vector([8, 0, 0]), xadapter)

    print("=" * 8)
    if model:
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

    # print("-" * 8)
    # print("Lap Time: {}".format(stat.lap_time))

if __name__ == "__main__":
    main()