#coding:utf-8
import os
import sys
import numbers

from . import ast
from ..exceptions import * # pylint: disable=W0614

class ConstraintIR(ast.Ast):
    def is_variable(self):
        return False

    def get_variables(self):
        return VariableList()

    def get_assume_nodes(self):
        return ConstraintList()    

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

class ConstraintList(list, ConstraintIR):
    def __add__(self, other):
        return ConstraintList(super(ConstraintList, self).__add__(other))

    def get_variables(self):
        res = []
        for const in self:
            res += const.get_variables()
        return VariableList(sorted(set(res)))

    def get_assume_nodes(self):
        res = []
        for const in self:
            res += const.get_assume_nodes()
        return VariableList(sorted(set(res)))

class Term(ast.Term, ConstraintIR):
    pass

class UniOp(ast.UniOp, ConstraintIR):
    def get_variables(self):
        if isinstance(self.value, ConstraintIR):
            return self.value.get_variables()
        else:
            return VariableList()

class BinOp(ast.BinOp, ConstraintIR):
    def get_variables(self):
        return VariableList(set(self.left.get_variables() + self.right.get_variables()))

    def get_assume_nodes(self):
        return VariableList(set(self.left.get_assume_nodes() + self.right.get_assume_nodes()))

class VariableType(ast.Ast):
    pass

class Register(VariableType):
    def __init__(self, name):
        assert name is not None
        if sys.version_info.major == 2:
            if isinstance(name, unicode): # pylint: disable=E0602
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
        assert(isinstance(scale, numbers.Integral))
        assert(isinstance(disp, numbers.Integral))
        self.kind = self.__class__.__name__
        self.base = base
        self.index = index
        self.scale = scale
        self.disp = disp
    
    def __repr__(self):
        return "{}(base={}, index={}, scale={}, disp={})".format(self.kind, self.base, self.index, self.scale, self.disp)

class Function(VariableType):
    def __init__(self, name, args):
        self.kind = self.__class__.__name__
        self.name = name
        self.args = args

    def __repr__(self):
        return "{}({}, {})".format(self.kind, self.name, self.args)

### NOTE: Variable but don't need to handle in tracer (Internal use)
### Refactor: rename to VirtualVariable and use get_virtual_variable() ?
class NullType(VariableType):
    pass

class Variable(ConstraintIR):
    def __init__(self, name, size, addr, vtype, objfile=None):
        assert isinstance(vtype, VariableType)
        assert objfile is None or isinstance(objfile, str)
        self.kind = self.__class__.__name__
        self.name = name
        self.size = size
        self.addr = addr
        self.vtype = vtype # REFACTER: want to rename from vtype to value
        self.objfile = objfile

    def __eq__(self, other):
        if isinstance(other, Variable):
            return (self.name == other.name) and (self.size == other.size) and (self.addr == other.addr) and (self.objfile == other.objfile)
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
        if self.objfile:
            return "{}({}, {}, {:#x}, {}, in {})".format(self.kind, self.name, self.size, self.addr, self.vtype, os.path.basename(self.objfile))
        else:
            return "{}({}, {}, {:#x}, {})".format(self.kind, self.name, self.size, self.addr, self.vtype)

    def __hash__(self):
        return hash(self.__repr__())

    def is_variable(self):
        return True

    def get_variables(self):
        if self.is_variable():
            return VariableList([self])
        else:
            return VariableList()

class Top(Term):
    def __init__(self):
        self.kind = self.__class__.__name__

class Bottom(Term):
    def __init__(self):
        self.kind = self.__class__.__name__

class Value(UniOp):
    def __repr__(self):
        return "{}({:#x})".format(self.kind, self.value)

class Not(UniOp):
    pass

class Assume(UniOp):
    def get_assume_nodes(self):
        return ConstraintList([self])

### Logical AND (∧)
class Land(BinOp):
    pass

### Logical OR (∨)
class Lor(BinOp):
    pass

class Band(BinOp):
    pass

class Bor(BinOp):
    pass

class Eq(BinOp):
    pass

class Ne(BinOp):
    pass

class Lt(BinOp):
    pass

class Le(BinOp):
    pass

class Gt(BinOp):
    pass

class Ge(BinOp):
    pass

class Assign(BinOp):
    pass

class Void(Variable):
    def __init__(self):
        self.kind = self.__class__.__name__

    def __repr__(self):
        return "{}()".format(self.kind)

    def is_variable(self):
        return False

class Label(Variable):
    def __init__(self, name):
        self.kind = self.__class__.__name__
        self.name = name

    def __repr__(self):
        return "{}({})".format(self.kind, self.name)

    def is_variable(self):
        return False


### REFACOTER: Is this really required?
class FuncArg(Variable):
    def __init__(self, call, name, addr=None):
        name = "{}_{}".format(call.name, name)
        if addr is None:
            addr = call.addr
        super(FuncArg, self).__init__(name, call.size, call.addr, call.vtype, call.objfile)
        self.kind = self.__class__.__name__

    def is_variable(self):
        return False

class FuncCallRet(ConstraintIR):
    def __init__(self, addr, value):
        self.kind = self.__class__.__name__
        self.addr = addr
        self.value = value

    def __repr__(self):
        return "{}({:#x}, {})".format(self.kind, self.addr, self.value)

class Call(Variable):
    def __init__(self, ret, args, addr, objfile):
        assert isinstance(ret, FuncCallRet)
        assert args is None or isinstance(args, list)
        self.kind = self.__class__.__name__
        self.name = "Call_{}_{:x}".format(self.__class__.__name__, addr)
        self.size = 0
        self.addr = addr
        self.vtype = Function(self.__class__.__name__, args)
        self.objfile = objfile
        self.args = self.__args(args) # define after self.object definition
        # self.ret = Variable("{}_return".format(self.name), 8, ret.addr, ret.value, objfile)
        self.ret = Label("{}_return".format(self.name))

    def __repr__(self):
        return "Call.{}({}, {}, {:#x}, in {})".format(self.kind, self.ret, self.args, self.addr, self.objfile)

    def __args(self, args):
        res = []
        for i, v in enumerate(args):
            if isinstance(v, Register):
                res.append(Variable("{}_arg{}".format(self.name, i), 8, self.addr, v, self.objfile))
            elif isinstance(v, Variable):
                res.append(v)
            else:
                raise UnhandledCaseError("arg {} is not Register or Variable".format(v))
        return res

    def get_variables(self):
        return VariableList([self])

class Strncmp(Call):
    def __init__(self, *args, **kwargs):
        super(Strncmp, self).__init__(*args, **kwargs)
        self.s1 = FuncArg(self, "s1")
        self.s2 = FuncArg(self, "s2")
        self.n = FuncArg(self, "n")


if __name__ == "__main__":
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

    print("[*] Assume node")
    res = ConstraintList([Land(Assume(Value(1)), Top()), Assume(Value(2))]).get_assume_nodes()
    print(res)
    assert(res == [Assume(Value(1)), Assume(Value(2))])
