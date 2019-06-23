from sage.all_cmdline import *   # import sage library

from .ast import constraint as C
from .ast import loss_function as L
from .exceptions import *
from .loss_function import L_op

def e(c):
    if isinstance(c, C.Lt):
        return L.Lt(e(c.left), e(c.right))
    if isinstance(c, C.Gt):
        return L.Gt(e(c.left), e(c.right))
    if isinstance(c, C.Le):
        return L.Le(e(c.left), e(c.right))
    if isinstance(c, C.Ge):
        return L.Ge(e(c.left), e(c.right))
    if isinstance(c, C.Eq):
        return L.Eq(e(c.left), e(c.right))
    if isinstance(c, C.Ne):
        return L.Ne(e(c.left), e(c.right))
    if isinstance(c, C.Value):
        return c.value
    if isinstance(c, C.Variable):
        return c.name
    raise UnhandledCaseError("encode: c={}".format(c))

def encode_constraint_to_loss_function_ast(constraint):
    if isinstance(constraint, list):
        assert(len(constraint) != 0)
        if len(constraint) == 1:
            return e(constraint[0])
        else:
            return L.Land(e(constraint[0]), encode_constraint_to_loss_function_ast(constraint[1:]))
    else:
        return e(constraint)

def Encode(constraints):
    L = encode_constraint_to_loss_function_ast(constraints)
    variables_names = map(lambda _: _.name, constraints.get_variables())
    print("variables_names = {}".format(variables_names))
    var(' '.join(variables_names))
    eval_statement = "symbolic_expression({}).function({})".format(L, ', '.join(variables_names))

    eval_locals = {}
    eval_locals.update(L_op)
    for v in variables_names:
        eval_locals.update({v: var(v)})

    print("sage_eval({}, locals={})".format(eval_statement, eval_locals))
    L = sage_eval(eval_statement, locals=eval_locals)
    print("L = {}".format(L))
    return L

if __name__ == "__main__":
    res = encode_constraint_to_loss_function_ast(C.Eq(C.Value(1), C.Variable('a', 4, 0x1000, C.Register('r'))))
    print("{!r}".format(res))
    res = encode_constraint_to_loss_function_ast([C.Eq(C.Value(1), C.Value(1)), C.Ne(C.Value(1), C.Value(1))])
    print("{!r}".format(res))