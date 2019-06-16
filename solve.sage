import subprocess
import os, sys
import json

from engine import *

class X():
    def __init__(self, args=[], stdin=None, files={}):
        self.args = args
        self.stdin = stdin
        self.files = files

    def __repr__(self):
        return "{}(args={}, stdin={}, files={})".format(self.__class__.__name__, self.args, self.stdin, self.files)

class Program:
    def __init__(self, program, xadapter):
        assert isinstance(program, str), "'program` must be a path to program"
        assert callable(xadapter), "`adapter` must be a fucntion"
        self.program = program
        self.xadapter = xadapter

    def call(self, x):
        assert isinstance(x, X), "fail: x = {}".format(x)
        p = subprocess.Popen([self.program] + x.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stdin = p.communicate()
        # print(stdout)

        y = {}
        for x in stdout.split(b'\n'):
            if x.startswith(b'{'):
                y = json.loads(x)
        return [y['x_0'], y['x_len']]

    def call_with_xadapter(self, x):
        return self.call(self.xadapter(x))

def strip_null(s):
    first_null_pos = s.find('\x00')
    return s[:first_null_pos]

def xadapter(v):
    # print("adapter: x = {}".format(x))
    try:
        s = ''.join(map(lambda _: chr(_) if _ > 0 else '\x00', v.list()))
        s = strip_null(s)
        return X(args=[s]) # sage var -> program input
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> v = {}".format(x))
        exit(1)

def vector_to_string(v):
    try:
        s = ''.join(map(lambda _: chr(_) if _ > 0 else '\x00', v.list()))
        return s
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, v))
        traceback.print_exc()
        print("-> v = {}".format(v))
        exit(1)

def test(N):
    print("[*] test")
    x = X(args=['aaa'])
    y = p.call(x)
    print("y = {}".format(y))

def main(N):
    print("[*] main")

    var('x_0 x_len')
    L(x_0, x_len) = L_a_eq_b(x_0, ord('#')) + L_a_eq_b(x_len, 3)

    model = NeuSolv(N, L, zero_vector(8))

    print("model: {}".format(model))
    # print("-> {!r}".format(vector_to_string(model)))
    print("-> {!r}".format(xadapter(model)))

if __name__ == "__main__":
    p = Program('sample/simple-if-statement-tree2', xadapter)
    N = p.call_with_xadapter
    test(N)
    main(N)