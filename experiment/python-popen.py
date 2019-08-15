import sys
import os
import subprocess

p = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
print("pid = {}".format(p.pid))
os.system("gdb -q -p {}".format(p.pid))
stdout, _ = p.communicate()
print(stdout)