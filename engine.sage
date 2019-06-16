#!/usr/bin/sage
#coding: utf8

import time

class UnexpectedException(Exception):
    pass

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

alpha = 1e-6
beta = -1e-6
epsilon = 1

L_a_lt_b(a, b) = max_symbolic(a - b + alpha, 0)
L_a_gt_b(a, b) = max_symbolic(b - a + alpha, 0)
L_a_le_b(a, b) = max_symbolic(a - b, 0)
L_a_ge_b(a, b) = max_symbolic(b - a, 0)
L_a_eq_b(a, b) = abs(a - b + alpha)
L_a_ne_b(a, b) = max_symbolic(-1, -1 * abs(a - b + beta))
L_land(L_S1, L_S2) = L_S1 + L_S2
L_lor(L_S1, L_S2) = min_symbolic(L_S1, L_S2)

def D_x_f(f, x):
    n = len(x)
    m = len(f(x))
    res = []
    # NOTE: Calcuate transpose of $D_x f$
    for i in range(n):
        row = []
        dxi = zero_vector(n)
        dxi[i] = 1
        for j in range(m):
            row.append((f(x + dxi)[j] - f(x)[j]) / dxi.norm())
        res.append(row)
    return matrix(res).transpose()

def NeuSolv(N, L, x0):
    
    grad_L = L.gradient()
    print("L = {}".format(L))
    print("∇L = {}".format(grad_L))

    max_trial = 50
    x, y = [None for x in range(max_trial + 1)], [None for x in range(max_trial + 1)]

    x[0] = x0

    for k in range(max_trial):
        stat.lap_start()

        y[k] = N(x[k])
        print("x[{}] = {}".format(k, x[k]))
        print("y[{}] = {}".format(k, y[k]))

        print("L(y[{}])) = {}".format(k, L(*y[k])))
        if L(*N(x[k])) <= 1e-2: 
            return x[k]

        grad_L_N_x = grad_L(*y[k]) * D_x_f(N, x[k])
        x[k + 1] = x[k] - epsilon * grad_L_N_x

        stat.lap_end()

    return None