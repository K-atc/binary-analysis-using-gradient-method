#!/usr/bin/sage
#coding: utf8
import subprocess
import json
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

class X():
    def __init__(self, args=[], stdin=None, files={}):
        self.args = args
        self.stdin = stdin
        self.files = files

    def __repr__(self):
        return "{}(args={}, stdin={}, files={})".format(self.__class__.__name__, self.args, self.stdin, self.files)

class Program:
    def __init__(self, program, xadapter, yadapter):
        assert isinstance(program, str), "'program` must be a path to program"
        assert callable(xadapter), "`adapter` must be a fucntion"
        self.program = program
        self.xadapter = xadapter
        self.yadapter = yadapter

    def call(self, x):
        assert isinstance(x, X), "fail: x = {}".format(x)
        p = subprocess.Popen([self.program] + x.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stdin = p.communicate()
        for x in stdout.split(b'\n'):
            if x.startswith(b'{'):
                y = json.loads(x)
        assert y
        return y

    def call_with_adapter(self, x):
        return self.yadapter(self.call(self.xadapter(x)))

def strip_null(s):
    first_null_pos = s.find('\x00')
    return s[:first_null_pos]

def vector_to_string(v):
    try:
        s = ''.join(map(lambda _: chr(_) if _ > 0 else '\x00', v.list()))
        return s
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, v))
        traceback.print_exc()
        print("-> v = {}".format(v))
        exit(1)


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