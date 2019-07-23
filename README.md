最急降下法を制約ソルバーに用いたシンボリック実行
====

```shell
./solve.sh SOLVER_SAGE_FILE
```

TODO：
* プロビジョン
* fileのインストール

```shell
### test inspector
python3 test-inspector.py
```

```shell
### install frida-gadget
wget https://github.com/frida/frida/releases/download/12.6.6/frida-gadget-12.6.6-linux-x86_64.so.xz
unxz frida-gadget-12.6.6-linux-x86_64.so.xz 
```

sample.tar の作り方

```shell
tar cf sample.tar sample/
```

sage shell sで pip install を実行。

```
vagrant@ubuntu-18:/vagrant$ sage -sh

Starting subshell with Sage environment variables set.  Don't forget
to exit when you are done.  Beware:
 * Do not do anything with other copies of Sage on your system.
 * Do not use this for installing Sage packages using "sage -i" or for
   running "make" at Sage's root directory.  These should be done
   outside the Sage shell.

Bypassing shell configuration files...

Note: SAGE_ROOT=/usr/share/sagemath
(sage-sh) vagrant@ubuntu-18:vagrant$ pip install -r /vagrant/requirements.txt
```

memo:

```
alpha = 1e-6
beta = -1e-6

Lt(a, b) = max(a - b + alpha, 0) # S ::= a < b
Gt(a, b) = max(b - a + alpha, 0) # S ::= a > b
Le(a, b) = max(a - b, 0)
Ge(a, b) = max(b - a, 0)
Eq(a, b) = abs(a - b + alpha)
Ne(a, b) = max(-1, -1 * abs(a - b + beta))
Land(L_S1, L_S2) = L_S1 + L_S2
Lor(L_S1, L_S2) = min(L_S1, L_S2)
```

To watch open files:

```shell
watch -n1 'lsof -p `pgrep -f "python2 solve-file.sage.py" | tail -n1`'
```