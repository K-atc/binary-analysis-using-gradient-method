最急降下法を制約ソルバーに用いたシンボリック実行
====

```shell
./solve.sh SOLVER_SAGE_FILE
```

```shell
### install frida-gadget
wget https://github.com/frida/frida/releases/download/12.6.6/frida-gadget-12.6.6-linux-x86_64.so.xz
unxz frida-gadget-12.6.6-linux-x86_64.so.xz 
```

```shell
### compile engine.py
sage -preparse engine.sage && mv engine.sage.py engine.py
```