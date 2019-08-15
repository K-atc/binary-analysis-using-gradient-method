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
    def __repr__(self):
        return "{}".format(self.kind) # symbolic constant

    def get_variables(self):
        return VariableList()

class UniOp(ast.UniOp, LossFunctionIR):
    def get_variables(self):
        return self.value.get_variables()

class BinOp(ast.BinOp, LossFunctionIR):
    def get_variables(self):
        return VariableList(set(self.left.get_variables() + self.right.get_variables()))

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
        self.kind = self.__class__.__name__
        self.name = name

    def __repr__(self):
        return "{}".format(self.name)

    def __eq__(self, other):
        if isinstance(other, Variable):
            return (self.name == other.name)
        else:
            return False

    def __hash__(self):
        return hash(self.__repr__())

    def get_variables(self):
        return VariableList([self])

class Vector(Variable):
    def __init__(self, name):
        self.kind = self.__class__.__name__
        self.name = name


if __name__ == "__main__":
    print("[*] repr")
    print(Lor(Eq(Variable('x'), Value(0)), Lt(Variable('y'), Value(1))))
    print("[*] get_variables")
    v1 = Variable('v1')
    assert(Eq(v1, v1).get_variables() == VariableList([v1]))