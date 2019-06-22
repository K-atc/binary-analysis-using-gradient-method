#!/usr/bin/python
import subprocess
import io

stdin = io.BytesIO(b"Hey! This is test")
p = subprocess.Popen(['/bin/cat'], stdin=stdin)
p.communicate()
