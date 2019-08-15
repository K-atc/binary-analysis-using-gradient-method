#!/usr/bin/sage
#coding: utf8

# from sage.manifolds.operators import *

# E = EuclideanSpace(3)

f(x, y) = x ^ 2 + x * y
# f = E.scalar_field(x ** 2 + x * y, name='f')

print("f = {}".format(f))
print("∂f/∂x = {}".format(f.diff(x)))
print("∇f = {}".format(f.gradient()))

print("f(1, 2) = {}".format(f(1, 2)))
a = [1, 2]
print("f({}) = {}".format(a, f(*a)))

print("(1, 0, 0) / ||(0, 1, 0)|| = {}".format(vector([1, 0, 0]) / vector([0, 1, 0]).norm()))

mip.<av, bv> = MixedIntegerLinearProgram()

var('a b')
alpha = 1
# Lt(a, b) = max(a - b + alpha, 0) # => 'ImportError: cannot import name create_prompt_application'
Lt(a, b) = max_symbolic(a - b + alpha, 0)
VEq(av, bv) = (av - bv).norm()

v1 = vector([1, 2, 3])
v0 = vector([0, 0, 0])

try:
    print("VEq = {}".format(VEq))
    print("∇VEq = {}".format(VEq.gradient()))
    print("Lt = {}".format(Lt))
    print("∇Lt = {}".format(Lt.gradient()))
    print("VEq(v1, v0) = {}".format(VEq(v1, v0)))
except Exception as e:
    import traceback
    traceback.print_exc()
    print(e)
    import ipdb; ipdb.set_trace()
