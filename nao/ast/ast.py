class Ast:
    pass

class Term(Ast):
    def __init__(self):
        self.kind = self.__class__.__name__
    
    def __eq__(self, other):
        if isinstance(other, Term):
            return self.kind == other.kind
        else:
            return False

    def __repr__(self):
        return "{}".format(self.kind)

class UniOp(Ast):
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

class BinOp(Ast):
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

class And(BinOp):
    pass

class Or(BinOp):
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

if __name__ == "__main__":
    print(Eq(Top(), Bottom()))

    print("[*] Compare ast")
    assert (Top().kind == Bottom().kind) == False
    print(Top().__eq__(Bottom()))
    assert Top().__eq__(Bottom()) == False
    assert((Top() == Bottom()) == False)
    assert((Eq(Top(), Bottom()) == Eq(Bottom(), Top())) == False)
    assert((Eq(Value(1), Value(2)) == Eq(Value(1), Value(2))) == True)

    print("[*] Compare Terms")
    print("Top() == Top() is {}".format(Top() == Top()))
    print("Top() is Top() is {}".format(Top() is Top()))
    print("isinstance(Top(), Top) is {}".format(isinstance(Top(), Top)))
    assert((Top() == Top()) == True)
    assert((Top() == Eq(Top(), Top())) == False)