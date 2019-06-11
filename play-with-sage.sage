#!/usr/bin/sage
#coding: utf8

# from sage.manifolds.operators import *

# E = EuclideanSpace(3)

x, y = var('x y')

f = x ** 2 + x * y
# f = E.scalar_field(x ** 2 + x * y, name='f')

print("f = {}".format(f))
print("∂f/∂x = {}".format(f.diff(x)))
print("∇f = {}".format(f.gradient()))