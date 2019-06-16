import subprocess
import os, sys
import json

from engine import *

class X():
    def __init__(self, args=[], stdin=None, files={}):
        self.args = args
        self.stdin = stdin
        self.files = files

    def __str__(self):
        return "(args={}, stdin={}, files={})".format(self.args, self.stdin, self.files)

class Program:
    def __init__(self, program):
        assert isinstance(program, str)
        self.program = program

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

def strip_null(s):
    first_null_pos = s.find('\x00')
    return s[:first_null_pos]

def adapter(x):
    # print("adapter: x = {}".format(x))
    try:
        v = ''.join(map(lambda v: chr(v) if v > 0 else '\x00', x.list()))
        v = strip_null(v)
        return X(args=[v]) # sage var -> program input
    except Exception, e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("-> x = {}".format(x))
        exit(1)

def main():
    p = Program('sample/simple-if-statement-tree2')
    N = p.call

    var('x_0 x_len')
    L(x_0, x_len) = L_a_eq_b(x_0, ord('#')) + L_a_eq_b(x_len, 3)

    x = X(args=['aaa'])
    y = N(x)
    print("y = {}".format(y))

    NeuSolv(N, L, zero_vector(8), adapter)

if __name__ == "__main__":
    main()