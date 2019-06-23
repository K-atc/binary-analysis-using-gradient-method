from sage.all_cmdline import *   # import sage library

alpha = RealNumber('1e-6')
beta = RealNumber('-1e-6')

var("a,b")
var("L_S1,L_S2")

Lt = symbolic_expression(max(a - b + alpha, Integer(0)) ).function(a,b) # S ::= a < b
Gt = symbolic_expression(max(b - a + alpha, Integer(0)) ).function(a,b) # S ::= a > b
Le = symbolic_expression(max(a - b, Integer(0))).function(a,b)
Ge = symbolic_expression(max(b - a, Integer(0))).function(a,b)
Eq = symbolic_expression(abs(a - b + alpha)).function(a,b)
Ne = symbolic_expression(max(-Integer(1) , -Integer(1)  * abs(a - b + beta))).function(a,b)
Land = symbolic_expression(L_S1 + L_S2).function(L_S1,L_S2)
Lor = symbolic_expression(min(L_S1, L_S2)).function(L_S1,L_S2)

L_op = {'Lt': Lt, 'Gt': Gt, 'Le': Le, 'Ge': Ge, 'Eq': Eq, 'Ne': Ne, 'Land': Land, 'Lor': Lor}