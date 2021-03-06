#coding: utf8

from sage.all_cmdline import *   # import sage library

import sys

from nao.statistics import Statistics
from nao.util import close_dangling_files

stat = Statistics()

# NOTE: Calcuate transpose of $D_x f$
def D_x_f(f, x):
    @parallel()
    def __row(i):
        dxi = zero_vector(n)
        dxi[i] = Integer(1)
        f_x_plus_dxi = f(x + dxi)
        f_x = f(x)
        m = len(f_x)
        row = []
        for j in range(m):
            row.append((f_x_plus_dxi[j] - f_x[j]) / dxi.norm())
        return row

    n = len(x)
    res = []
    for (_, d_i) in sorted(list(__row(range(n)))):
        assert d_i is not 'NO DATA', 'Exception occured in this thread'
        res.append(d_i)
    return matrix(res).transpose()

def NeuSolv(N, L, x0, xadapter):
    assert callable(N)
    assert callable(L)

    epsilon = RealNumber('0.1') # Learning Late
    gamma = RealNumber('0.9') # momentum

    print("\n[*] === NeuSolv() ===")
    
    grad_L = L.gradient()
    print("L = {}".format(L))
    print("∇L = {}".format(grad_L))

    max_trial = Integer(5000)
    x, y = [None for x in range(max_trial + Integer(1))], [None for x in range(max_trial + Integer(1))]

    x[Integer(0)] = x0
    x[Integer(1)] = x0

    for k in range(Integer(1), max_trial):
        stat.lap_start()

        ### Routine
        y[k] = N(x[k])
        print("x[{}] = {}".format(k, x[k]))
        print("      = {}".format(xadapter(x[k])))
        print("y[{}] = {}".format(k, y[k]))

        ### Check current loss
        print("L(y[{}])) = {}".format(k, L(*y[k])))
        if L(*y[k]) <= RealNumber('1e-2'): 
            stat.lap_end()
            return x[k]

        ### Update x
        try:
            grad_L_N_x = grad_L(*y[k]) * D_x_f(N, x[k])
        except Exception as e:
            sys.stdout.flush()
            # print("grad_L(*y[k]) = {}".format(grad_L(*y[k])))
            # print("D_x_f(N, x[k]) = {}".format(D_x_f(N, x[k])))
            raise e

        x[k + Integer(1)] = x[k] + gamma * (x[k] - x[k - Integer(1)]) - epsilon * grad_L_N_x # Momentum
        # x[k + 1] = x[k] - epsilon * grad_L_N_x # Normal gradient (SGD)

        stat.lap_end()

        close_dangling_files()

    return None

