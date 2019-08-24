#!/usr/bin/sage
#coding: utf8
import sys

from nao.statistics import Statistics
from nao.util import close_dangling_files

stat = Statistics()

# NOTE: Calcuate transpose of $D_x f$
def D_x_f(f, x):
    @parallel()
    def __row(i):
        dxi = zero_vector(n)
        dxi[i] = 1
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

    epsilon = 0.1 # Learning Late
    gamma = 0.9 # momentum

    print("\n[*] === NeuSolv() ===")
    
    grad_L = L.gradient()
    print("L = {}".format(L))
    print("∇L = {}".format(grad_L))

    max_trial = 2000
    x, y = [None for x in range(max_trial + 1)], [None for x in range(max_trial + 1)]

    x[0] = x0
    x[1] = x0

    for k in range(1, max_trial):
        stat.lap_start()

        ### Routine
        y[k] = N(x[k])
        print("x[{}] = {}".format(k, x[k]))
        print("      = {}".format(xadapter(x[k])))
        print("y[{}] = {}".format(k, y[k]))

        ### Check current loss
        print("L(y[{}])) = {}".format(k, L(*y[k])))
        if L(*y[k]) <= 1e-2: 
            return x[k]

        ### Update x
        try:
            grad_L_N_x = grad_L(*y[k]) * D_x_f(N, x[k])
        except Exception as e:
            sys.stdout.flush()
            # print("grad_L(*y[k]) = {}".format(grad_L(*y[k])))
            # print("D_x_f(N, x[k]) = {}".format(D_x_f(N, x[k])))
            raise e

        x[k + 1] = x[k] + gamma * (x[k] - x[k - 1]) - epsilon * grad_L_N_x # Momentum
        # x[k + 1] = x[k] - epsilon * grad_L_N_x # Normal gradient (SGD)

        # ### Check if updating x is stopped
        # if k > 2 and x[k + 1] == x[k]:
        #     return None

        # ### Slow down learning late in late epic
        # if L(*y[k]) < 3.0:
        #     epsilon *= 0.95
        #     gamma *= 0.95

        stat.lap_end()

        close_dangling_files()

    return None