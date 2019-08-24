import os, sys
import functools
import struct

from engine import *
from nao.util import strip_null, X, Program, Tactic, FixedValue
from nao.encoder import encode_constraint_to_loss_function_ast
from nao.ast import constraint as C

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
        return X(args=[s]) # sage var -> program input
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
                res.append(y[v.name])
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
    main_file = "sample/ais3_crackme"
    # p = Program(main_file, xadapter, yadapter, debug=True)
    p = Program(main_file, xadapter, yadapter)

    """
  4005ae:	0f b6 00             	movzx  eax,BYTE PTR [rax]
  4005b1:	84 c0                	test   al,al
  4005b3:	0f 85 78 ff ff ff    	jne    400531 <verify+0x11>

  4005d4:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
  4005d8:	74 11                	je     4005eb <main+0x26>

    .text:000000000040058A 008 movzx   eax, encrypted[rax]
    .text:0000000000400591 008 cmp     al, [rbp+var_5]
    .text:0000000000400594 008 jz      short loc_4

  4005b9:	83 7d fc 17          	cmp    DWORD PTR [rbp-0x4],0x17
  4005bd:	0f 94 c0             	sete   al
  4005c0:	0f b6 c0             	movzx  eax,al
  4005c3:	5d                   	pop    rbp
  4005c4:	c3                   	ret    

  4005f9:	e8 22 ff ff ff       	call   400520 <verify>
  4005fe:	85 c0                	test   eax,eax
  400600:	74 0c                	je     40060e <main+0x49>
    """

    ### Generate constraints on y
    find_addr = 0x400602
    constraints = p.get_constraints(Tactic.near_path_constraint, rebased_addr=find_addr)
    # constraints.append(C.Eq(C.Variable('var_4005D4_left', 1, 0x5d4, C.Memory(C.Register('rbp'), None, 1, -4)), C.Value(2))) # argc == 2
    constraints.append(C.Eq(C.Variable('var_400591_left', 1, 0x591, C.Register('al')), C.Variable('var_400591_right', 1, 0x591, C.Memory(C.Register('rbp'), None, 1, -5))))
    constraints.append(C.Eq(C.Variable('var_4005B9_left', 1, 0x5b9, C.Memory(C.Register('rbp'), None, 1, -4)), C.Value(0x17))) # len(argv[1]) == 0x17
    # constraints.append(C.Eq(C.Variable('var_4005B1_left', 1, 0x5b1, C.Register('al')), C.Value(0))) # argv[1][i] is not null
    print("y constraints = {}".format(constraints))
    # exit(1)

    ### Define function N
    N = p.N(constraints)

    ### Define loss function
    L = p.L(constraints)

    ### Solve constraints
    ### TODO: auto set initial x 
    # model = NeuSolv(N, L, zero_vector(18))
    
    # model = NeuSolv(N, L, vector(map(lambda _: ord(_), list(b"ais3{I_tak3_g00d_n0t3s}"))), xadapter)
    # model = NeuSolv(N, L, vector(map(lambda _: ord(_), list(b"azs3{I_tak3_g00d_n0t3s}"))), xadapter)
    # model = NeuSolv(N, L, vector(map(lambda _: ord(_), list('AAAAAAAAAAAAAAAAAAAAAAA'))), xadapter)
    model = NeuSolv(N, L, zero_vector(18), xadapter)

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

    print("-" * 8)
    print("Lap Time: {}".format(stat.lap_time))

if __name__ == "__main__":
    main()