from exceptions import *

class ConstraintIR:
    pass

class VariableList(list):
    def __add__(self, other):
        return VariableList(super(VariableList, self).__add__(other))

    def find(self, name=None, addr=None):
        if name:
            return VariableList(filter(lambda _: _.name == name, self))
        if addr:
            return VariableList(filter(lambda _: _.addr == addr, self))
        raise UnhandledCaseError("VariableList.find(): provide `name` or `addr`")  

class ConstraintList(list):
    def __add__(self, other):
        return ConstraintList(super(ConstraintList, self).__add__(other))

    def get_variables(self):
        res = []
        for const in self:
            res += const.get_variables()
        return VariableList(sorted(res))

class Term(ConstraintIR):
    def __init__(self):
        self.kind = self.__class__.__name__
    
    def __eq__(self, other):
        if isinstance(other, Term):
            return self.kind == self.kind
        else:
            return False

    def __repr__(self):
        return "{}".format(self.kind)

    def get_variables(self):
        return VariableList()

class UniOp(ConstraintIR):
    def __init__(self, value):
        self.kind = self.__class__.__name__
        self.value = value

    def __eq__(self, other):
        if isinstance(other, UniOp):
            return (self.kind == other.kind) and (self.value == other.value)
        else:
            return False

    def __repr__(self):
        return "{}({})".format(self.kind, self.value)

    def get_variables(self):
        if isinstance(self.value, ConstraintIR):
            return self.value.get_variables()
        else:
            return VariableList()

class BinOp(ConstraintIR):
    def __init__(self, left, right):
        self.kind = self.__class__.__name__
        self.left = left
        self.right = right

    def __eq__(self, other):
        if isinstance(other, BinOp):
            return (self.kind == other.kind) and (self.left == other.left) and (self.right == other.right)
        else:
            return False

    def __repr__(self):
        return "{}({}, {})".format(self.kind, self.left, self.right)

    def get_variables(self):
        return self.left.get_variables() + self.right.get_variables()

class VariableType:
    def __init__(self):
        self.kind = self.__class__.__name__

class Register(VariableType):
    def __init__(self, name):
        assert name is not None
        if isinstance(name, unicode):
            name = str(name)
        assert isinstance(name, str), "name = {} ({})".format(name, type(name))
        self.kind = self.__class__.__name__        
        self.name = name
    
    def __repr__(self):
        return "{}({})".format(self.kind, self.name)

class Memory(VariableType):
    def __init__(self, base, index, scale, disp):
        assert(isinstance(base, Register))
        assert(isinstance(index, Register) or index is None)
        assert(isinstance(scale, int))
        assert(isinstance(disp, int))
        self.kind = self.__class__.__name__
        self.base = base
        self.index = index
        self.scale = scale
        self.disp = disp
    
    def __repr__(self):
        return "{}(base={}, index={}, scale={}, disp={})".format(self.kind, self.base, self.index, self.scale, self.disp)

class Variable(ConstraintIR):
    def __init__(self, name, size, addr, vtype):
        assert(isinstance(vtype, VariableType))
        self.kind = self.__class__.__name__
        self.name = name
        self.size = size
        self.addr = addr
        self.vtype = vtype

    def __eq__(self, other):
        if isinstance(other, Variable):
            return (self.name == other.name) and (self.size == other.size) and (self.addr == self.addr)
        else:
            return False

    def __lt__(self, other):
        if self.addr < other.addr:
            return True
        if (self.addr == other.addr) and (self.name < other.name):
            return True
        if (self.name == other.name) and (self.size <= other.size):
            return True
        return False

    def __repr__(self):
        return "{}({}, {}, {:#x}, {})".format(self.kind, self.name, self.size, self.addr, self.vtype)

    def get_variables(self):
        return VariableList([self])

class Top(Term):
    pass

class Value(UniOp):
    def __repr__(self):
        return "{}({:#x})".format(self.kind, self.value)

class Not(UniOp):
    pass

class And(BinOp):
    pass

class Or(BinOp):
    pass

class Eq(BinOp):
    pass

class Lt(BinOp):
    pass

class Le(BinOp):
    pass

class Gt(BinOp):
    pass

class Ge(BinOp):
    pass

if __name__ == "__main__":
    print(Eq(Value(1), Value(2)))
    print(Eq(Value(1), Top()))

    print("[*] Compare Terms")
    print("Top() == Top() is {}".format(Top() == Top()))
    print("Top() is Top() is {}".format(Top() is Top()))
    print("isinstance(Top(), Top) is {}".format(isinstance(Top(), Top)))
    assert((Top() == Top()) == True)
    assert((Top() == Eq(Top(), Top())) == False)

    print("[*] get_variables()")
    r = Register('r')
    var_a_4_1 = Variable('a', 4, 1, r)
    var_a_8_1 = Variable('a', 8, 1, r)
    var_b_4_2 = Variable('b', 4, 2, r)
    assert(Not(Value(1)).get_variables() == [])
    assert(Eq(Value(1), var_a_4_1).get_variables() == [var_a_4_1])
    assert(sorted([var_a_4_1, var_b_4_2, var_a_8_1]) == [var_a_4_1, var_a_8_1, var_b_4_2])

    print("[*] VariableList")
    print("VariableList[var_a_4_1] == [var_a_4_1] is {}".format(VariableList([var_a_4_1]) == [var_a_4_1]))
    assert(VariableList([var_a_4_1, var_b_4_2]).find(name='a') == VariableList([var_a_4_1]))
    assert(VariableList([var_a_4_1, var_b_4_2]).find(addr=2) == VariableList([var_b_4_2]))

    print("[*] ConstrintList")
    res = ConstraintList([Top(), Eq(var_b_4_2, var_a_4_1), var_a_8_1]).get_variables()
    assert(isinstance(res, VariableList))
    assert(res == [var_a_4_1, var_a_8_1, var_b_4_2])