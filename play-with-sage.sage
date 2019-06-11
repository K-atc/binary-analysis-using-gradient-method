#!/usr/bin/sage
#coding: utf8

# from sage.manifolds.operators import *

# E = EuclideanSpace(3)

x, y = var('x y')

f(x, y) = x ^ 2 + x * y
# f = E.scalar_field(x ** 2 + x * y, name='f')

print("f = {}".format(f))
print("∂f/∂x = {}".format(f.diff(x)))
print("∇f = {}".format(f.gradient()))

print("f(1, 2) = {}".format(f(1, 2)))
a = [1, 2]
print("f({}) = {}".format(a, f(*a)))

print("(1, 0, 0) / ||(0, 1, 0)|| = {}".format(vector([1, 0, 0]) / vector([0, 1, 0]).norm()))