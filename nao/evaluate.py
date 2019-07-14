from sage.all_cmdline import *   # import sage library

from .ast import constraint as C
from .exceptions import *

def to_vector(x):
    return vector([ord(_) for _ in x])

def e(c, context):
    # print("[*] e(c={}, context={})".format(c, context))
    if isinstance(c, C.Call):
        if isinstance(c, C.Strncmp):
            if c.s1.name in context and c.s2.name in context:
                context[c.ret.name] = (to_vector(context[c.s1.name]) - to_vector(context[c.s2.name])).norm()
        else:
            raise UnhandledCaseError("Missing case for Call: {}".format(c))
    elif isinstance(c, C.UniOp):
        return e(c.value, context)
    elif isinstance(c, C.BinOp):
        res = {}
        res.update(e(c.left, context))
        res.update(e(c.right, context))
        return res
    else:
        pass
    assert context is not None
    return context

def evaluate_constraint_ast(constraint_ast, context):
    # print("[*] evaluate_constraint_ast(constraint_ast={}, context={})".format(constraint_ast, context))
    assert isinstance(constraint_ast, C.ConstraintIR)
    assert context is not None
    if isinstance(constraint_ast, C.ConstraintList):
        res = dict()
        for x in constraint_ast:
            try:
                res.update(e(x, context))
            except Exception as e_:
                import ipdb; ipdb.set_trace()
        return res
    return e(constraint_ast, context)