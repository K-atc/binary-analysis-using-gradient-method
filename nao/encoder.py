from sage.all_cmdline import *   # import sage library

from .ast import constraint as C
from .ast import loss_function as L
from .exceptions import *
from .loss_function import L_op



def e(c):
    if isinstance(c, C.Call):
        if isinstance(c, C.Strncmp):
            return L.Variable(c.ret.name)
        raise UnhandledCaseError("Missing case for Call: {}".format(c))
    if isinstance(c, C.Land):
        return L.Land(e(c.left), e(c.right))
    if isinstance(c, C.Lor):
        return L.Lor(e(c.left), e(c.right))
    if isinstance(c, C.Band):
        return L.Band(e(c.left), e(c.right))
    if isinstance(c, C.Bor):
        return L.Bor(e(c.left), e(c.right))
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
        return L.Value(c.value)
    if isinstance(c, C.Variable):
        return L.Variable(c.name)
    if isinstance(c, C.Assign): # Dismiss
        return L.Top()
    if isinstance(c, C.Assume): # Dismiss
        return L.Top()
    if isinstance(c, C.Top):
        return L.Top()
    raise UnhandledCaseError("Not handled: c={}".format(c))

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
    loss_function_ast = encode_constraint_to_loss_function_ast(constraints)
    print("[*] Encode(): loss_function_ast = {}".format(loss_function_ast))
    L_varaibles = loss_function_ast.get_variables()
    variables_names = map(lambda _: _.name, L_varaibles)
    # print("[*] Encode(): variables_names = {}".format(variables_names))
    var(' '.join(variables_names)) # pylint: disable=E0602
    eval_statement = "symbolic_expression({}).function({})".format(loss_function_ast, ', '.join(variables_names))

    eval_locals = {}
    eval_locals.update(L_op)
    for v in L_varaibles:
        eval_locals.update({v.name: var(v.name)}) # pylint: disable=E0602

    try:
        loss_function = sage_eval(eval_statement, locals=eval_locals) # pylint: disable=E0602
    except Exception as e:
        print("[*] sage_eval('{}', locals={})".format(eval_statement, eval_locals))
        raise e
    return loss_function

if __name__ == "__main__":
    res = encode_constraint_to_loss_function_ast(C.Eq(C.Value(1), C.Variable('a', 4, 0x1000, C.Register('r'))))
    print("{!r}".format(res))
    res = encode_constraint_to_loss_function_ast([C.Eq(C.Value(1), C.Value(1)), C.Ne(C.Value(1), C.Value(1))])
    print("{!r}".format(res))