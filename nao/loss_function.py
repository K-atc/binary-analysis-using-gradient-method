from sage.all_cmdline import *   # import sage library

alpha = RealNumber('1e-6')
beta = RealNumber('-1e-6')

var("a,b")
var(",".join("a{},b{}".format(i, i) for i in range(8)))
var("L_S1,L_S2")

Top = Integer(0)
Lt = symbolic_expression(max_symbolic(a - b + alpha, Integer(0)) ).function(a,b) # S ::= a < b
Gt = symbolic_expression(max_symbolic(b - a + alpha, Integer(0)) ).function(a,b) # S ::= a > b
Le = symbolic_expression(max_symbolic(a - b, Integer(0))).function(a,b)
Ge = symbolic_expression(max_symbolic(b - a, Integer(0))).function(a,b)
# Eq = symbolic_expression(abs(a - b + alpha)).function(a,b)
Eq = symbolic_expression((a - b) ** 2).function(a,b)
Ne = symbolic_expression(max_symbolic(-Integer(1) , -Integer(1)  * abs(a - b + beta))).function(a,b)
Land = symbolic_expression(L_S1 + L_S2).function(L_S1,L_S2)
Lor = symbolic_expression(min_symbolic(L_S1, L_S2)).function(L_S1,L_S2)

# VEq8 = symbolic_expression(abs(a0 - b0) + abs(a1 - b1) + abs(a2 - b2) + abs(a3 - b3) + abs(a4 - b4) + abs(a5 - b5) + abs(a6 - b6) + abs(a7 - b7)).function(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7)

L_op = {'Top': Top, 'Lt': Lt, 'Gt': Gt, 'Le': Le, 'Ge': Ge, 'Eq': Eq, 'Ne': Ne, 'Land': Land, 'Lor': Lor}