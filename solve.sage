#!/usr/bin/sage
#coding: utf8

# from sage.manifolds.operators import *

class UnexpectedException(Exception):
    pass

def grad(L, x):
    ret = []
    for x_i in x:
        ret.append(L.diff(x_i))
    return vector(ret)

a, b = var('a b')

alpha = 1
beta = -1

L_a_lt_b = max(a - b + alpha, 0)
L_a_gt_b = max(b - a + alpha, 0)
L_a_le_b = max(a - b, 0)
L_a_ge_b = max(b - a, 0)
L_a_eq_b = abs(a - b)
L_a_ne_b = max(-1, -1 * abs(a - b + beta))
L_land = lambda L_S1, L_S2: L_S1 + L_S2
L_lor = lambda L_S1, L_S2: min(L_S1, L_S2)

def strlen(x):
    # print("strlen: x = ", x, len(x))
    for i in range(len(x)):
        if x[i] == 0:
            return i
    return len(x) + 1
    raise UnexpectedException()

def r_N_r_xi(N, x, i):
    ret = []
    # print("(N, x, i) = ", N, x, i)
    # print("N.x count", N.__code__.co_argcount)
    dxi = vector([0 for _ in range(len(x))])
    dxi[i] = 1
    for j in range(N.__code__.co_argcount):
        ret.append(N(x + dxi)[j] - N(x)[j])
    return vector(ret)
    # print("x + dxi = ", (x + dxi))
    # print("strlen(x + dxi) = ", strlen(x + dxi))
    # print("strlen(x) = ", strlen(x))

"""
char[] x; // symbolized
unsigned int x_len = strlen(x);
assert(x[0] == 2 && x_len = 3);
"""
print("-" * 8)

x_len = var('x_len')
N = lambda x: vector([strlen(x)])
L_y = [x_len]
L = L_a_eq_b(L_y[0], 3) # <=> x_len == 2
grad_L = grad(L, L_y)
print("L = {}".format(L))
print("∇L = {}".format(grad_L))

x, y = [None for x in range(8)], [None for x in range(8)]

x[0] = vector([0, 0, 0, 0])

for k in range(4):
    print("x[{}] = {}".format(k, x[k]))
    y[k] = strlen(x[k])
    if L(y[k]) == 0: # ゼロ除算対策
        print("found!!")
        break
    r_z_r_x = [
        grad_L(y[k]).dot_product(r_N_r_xi(N, x[k], 0)),
        grad_L(y[k]).dot_product(r_N_r_xi(N, x[k], 1)),
        grad_L(y[k]).dot_product(r_N_r_xi(N, x[k], 2)),
        grad_L(y[k]).dot_product(r_N_r_xi(N, x[k], 3)),
        ]
    grad_L_N_x = vector(r_z_r_x)
    if grad_L_N_x.norm() == 0: # 勾配消失
        print("found!!")
        break
    x[k + 1] = x[k] - grad_L_N_x
