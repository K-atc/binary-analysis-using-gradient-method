#!/usr/bin/sage
#coding: utf8
import time

class Statistics:
    lap_time = []
    start_time = 0

    def __init__(self):
        pass

    def lap_start(self):
        self.start_time = time.time()
    
    def lap_end(self):
        end_time = time.time()
        self.lap_time.append(end_time - self.start_time)

stat = Statistics()

def D_x_f(f, x):
    n = len(x)
    m = len(f(x))
    res = []
    # NOTE: Calcuate transpose of $D_x f$
    for i in range(n):
        row = []
        dxi = zero_vector(n)
        dxi[i] = 1
        f_x_plus_dxi = f(x + dxi)
        f_x = f(x)
        for j in range(m):
            row.append((f_x_plus_dxi[j] - f_x[j]) / dxi.norm())
        res.append(row)
    return matrix(res).transpose()

def NeuSolv(N, L, x0, xadapter):
    assert callable(N)
    assert callable(L)

    epsilon = 0.5
    gamma = 0.9
    
    grad_L = L.gradient()
    print("L = {}".format(L))
    print("∇L = {}".format(grad_L))

    max_trial = 1000
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

        # ### Out of range check
        # ### FIXME: Impllement correctly
        # if x[k][0] >= 0x100:
        #     print("[!] Out of range value")
        #     break

        ### Check current loss
        print("L(y[{}])) = {}".format(k, L(*y[k])))
        if L(*y[k]) <= 1e-2: 
            return x[k]

        ### Update x
        grad_L_N_x = grad_L(*y[k]) * D_x_f(N, x[k])
        x[k + 1] = x[k] + gamma * (x[k] - x[k - 1]) - epsilon * grad_L_N_x # Momentum
        # x[k + 1] = x[k] - epsilon * grad_L_N_x # Normal gradient (SGD)

        ### Check if updating x is stopped
        if k > 1 and x[k + 1] == x[k]:
            return None

        if L(*y[k]) < 3.0:
            epsilon *= 0.95
            gamma *= 0.95

        stat.lap_end()

    return None