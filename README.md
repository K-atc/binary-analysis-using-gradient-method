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