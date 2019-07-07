import numbers

from . import ast
from ..exceptions import UnhandledCaseError

class LossFunctionIR(ast.Ast):
    pass

class VariableList(list):
    def __add__(self, other):
        return VariableList(super(VariableList, self).__add__(other))

    def find(self, name=None, objfile=None, addr=None):
        if name:
            return VariableList(filter(lambda _: _.name == name, self))
        if addr:
            if objfile:
                return VariableList(filter(lambda _: _.addr == addr and objfile in _.objfile, self))
            else:
                return VariableList(filter(lambda _: _.addr == addr, self))
        raise UnhandledCaseError("VariableList.find(): provide `name` or `addr`")  

class Term(ast.Term, LossFunctionIR):
    def get_variables(self):
        return VariableList()

class UniOp(ast.UniOp, LossFunctionIR):
    def get_variables(self):
        return self.value.get_variables()

class BinOp(ast.BinOp, LossFunctionIR):
    def get_variables(self):
        return self.left.get_variables() + self.right.get_variables()

### True
class Top(Term):
    pass

class Lt(BinOp):
    pass

class Gt(BinOp):
    pass

class Le(BinOp):
    pass

class Ge(BinOp):
    pass

class Eq(BinOp):
    pass

class Ne(BinOp):
    pass

class Land(BinOp):
    pass

class Lor(BinOp):
    pass

class Band(BinOp):
    pass

class Bor(BinOp):
    pass

class Value(UniOp):
    def __repr__(self):
        return "{}".format(self.value)

    def get_variables(self):
        return VariableList()

class Variable(UniOp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "{}".format(self.name)

    def get_variables(self):
        return VariableList([self])

class Vector(Variable):
    def __init__(self, name):
        # assert isinstance(value, VariableList)
        self.name = name
        # self.value = value

class VEq(BinOp):
    def __init__(self, left, right, n):
        assert isinstance(left, Vector)
        assert isinstance(right, Vector)
        assert isinstance(n, numbers.Number)
        self.left = left
        self.right = right
        self.n = n
    
    def __repr__(self):
        return "{}{}({}, {})".format(self.__class__.__name__, self.n, 
        # ', '.join(self.left),
        # ', '.join(self.right),
        ", ".join("{}_{}".format(self.left, i) for i in range(self.n)),
        ", ".join("{}_{}".format(self.right, i) for i in range(self.n)),
        )

    def get_variables(self):
        res = []
        for v in [self.left, self.right]:
            for i in range(self.n):
                res.append(Variable("{}_{}".format(v.name, i)))
        return VariableList(res)