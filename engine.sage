#!/usr/bin/sage
#coding: utf8
import subprocess
import json
import time

import util
import ir

stat = util.Statistics()

alpha = 1e-6
beta = -1e-6

L_a_lt_b(a, b) = max(a - b + alpha, 0) # S ::= a < b
L_a_gt_b(a, b) = max(b - a + alpha, 0) # S ::= a > b
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
        f_x_plus_dxi = f(x + dxi)
        f_x = f(x)
        for j in range(m):
            row.append((f_x_plus_dxi[j] - f_x[j]) / dxi.norm())
        res.append(row)
    return matrix(res).transpose()

def NeuSolv(N, L, x0):
    epsilon = 0.5
    gamma = 0.9
    
    grad_L = L.gradient()
    print("L = {}".format(L))
    print("∇L = {}".format(grad_L))

    max_trial = 300
    x, y = [None for x in range(max_trial + 1)], [None for x in range(max_trial + 1)]

    x[0] = x0
    x[1] = x0

    for k in range(1, max_trial):
        stat.lap_start()

        y[k] = N(x[k])
        print("x[{}] = {}".format(k, x[k]))
        print("y[{}] = {}".format(k, y[k]))

        print("L(y[{}])) = {}".format(k, L(*y[k])))
        if L(*N(x[k])) <= 1e-2: 
            return x[k]

        grad_L_N_x = grad_L(*y[k]) * D_x_f(N, x[k])
        x[k + 1] = x[k] + gamma * (x[k] - x[k - 1]) - epsilon * grad_L_N_x # Momentum
        # x[k + 1] = x[k] - epsilon * grad_L_N_x # Normal gradient (SGD)

        stat.lap_end()

    return None