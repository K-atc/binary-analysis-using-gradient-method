#!/usr/bin/sage
#coding: utf8

class UnexpectedException(Exception):
    pass

alpha = 1e-6
beta = -1e-6
epsilon = 1

L_a_lt_b(a, b) = max(a - b + alpha, 0)
L_a_gt_b(a, b) = max(b - a + alpha, 0)
L_a_le_b(a, b) = max(a - b, 0)
L_a_ge_b(a, b) = max(b - a, 0)
L_a_eq_b(a, b) = abs(a - b + alpha)
L_a_ne_b(a, b) = max(-1, -1 * abs(a - b + beta))
L_land(L_S1, L_S2) = L_S1 + L_S2
L_lor(L_S1, L_S2) = min(L_S1, L_S2)

def strlen(x):
    for i in range(len(x)):
        if x[i] <= 0:
            return i
    return len(x)
    raise UnexpectedException()

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
            row.append((N(x + dxi)[j] - N(x)[j]) / dxi.norm())
        res.append(row)
    return matrix(res).transpose()

def r_N_r_xi(N, x, i):
    ret = []
    dxi = zero_vector(len(x))
    dxi[i] = 1
    for j in range(len(N(x))):
        ret.append((N(x + dxi)[j] - N(x)[j]) / dxi.norm())
    return vector(ret)

"""
char[] x; // symbolized
unsigned int x_len = strlen(x);
assert(x[0] == 2 && x_len = 3);
"""
print("-" * 8)

var('x_len x_0')
N = lambda x: [x[0], strlen(x)]
L(x_0, x_len) = L_a_eq_b(x_0, 2) + L_a_eq_b(x_len, 3)
grad_L = L.gradient()
print("L = {}".format(L))
print("∇L = {}".format(grad_L))

max_trial = 40
x, y = [None for x in range(max_trial + 1)], [None for x in range(max_trial + 1)]

x[0] = vector([0, 0, 0, 0])

for k in range(max_trial):
    y[k] = N(x[k])
    print("x[{}] = {}".format(k, x[k]))
    print("y[{}] = {}".format(k, y[k]))

    print("L(y[k])) = {}".format(L(*y[k])))
    if L(*N(x[k])) <= 1e-2: 
        print("\n[*] found!! x = {}".format(x[k]))
        break 

    grad_L_N_x = grad_L(*y[k]) * D_x_f(N, x[k])
    x[k + 1] = x[k] - epsilon * grad_L_N_x
    # print("x[k+1] - x[k] = {}".format(x[k + 1] - x[k]))