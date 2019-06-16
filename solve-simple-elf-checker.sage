import os, sys

from engine import *

def xadapter(v):
    try:
        s = ''.join(map(lambda _: chr(round(_)) if _ > 0 else '\x00', v.list()))
        return X(stdin=s) # sage var -> program input
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> v = {}".format(x))
        exit(1)

def yadapter(y):
    try:
        return [y['e_ident0'], y['e_ident1'], y['e_ident2'], y['e_ident3'], y['ei_class']]
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> y = {}".format(y))
        exit(1)

def main(N):
    print()
    print("[*] main")

    ### Define loss function
    var('e_ident0 e_ident1 e_ident2 e_ident3 ei_class')
    L(e_ident0, e_ident1, e_ident2, e_ident3, ei_class) = L_a_eq_b(e_ident0, ord('\x7f')) + L_a_eq_b(e_ident1, ord('E')) + L_a_eq_b(e_ident2, ord('L')) + L_a_eq_b(e_ident3, ord('F')) + L_a_eq_b(ei_class, 2)

    ### Initial vector
    x0 = zero_vector(32)
    x0[0] = 0x41
    x0[1] = 0x41
    x0[2] = 0x41
    x0[3] = 0x41
    x0[4] = 0
    # x0[0] = 0x7f
    # x0[1] = ord('E')
    # x0[2] = ord('L')
    # x0[3] = ord('F')
    # x0[4] = 1

    ### Solve constraints
    model = NeuSolv(N, L, x0)

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
    ### Define function N
    p = Program('sample/simple-elf-checker', xadapter, yadapter)
    N = p.call_with_adapter

    main(N)