class Term:
    def __init__(self):
        self.kind = self.__class__.__name__
    
    def __eq__(self, other):
        if isinstance(other, Term):
            return self.kind == self.kind
        else:
            return False

    def __repr__(self):
        return "{}".format(self.kind)

class UniOp:
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

class BinOp:
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

class Variable:
    def __init__(self, name, size):
        self.kind = self.__class__.__name__
        self.name = name
        self.size = size

    def __eq__(self, other):
        if isinstance(other, Variable):
            return (self.name == other.name) and (self.size == other.size)
        else:
            return False

    def __repr__(self):
        return "{}({}, {})".format(self.kind, self.name, self.size)

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

    print("Top() == Top() is {}".format(Top() == Top()))
    print("Top() is Top() is {}".format(Top() is Top()))
    print("isinstance(Top(), Top) is {}".format(isinstance(Top(), Top)))

    assert((Top() == Eq(Top(), Top())) == False)