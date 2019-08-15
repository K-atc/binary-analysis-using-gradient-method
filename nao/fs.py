import os
import shutil
import random
import string
import time

class FileSystemException(Exception):
    pass

def WARN(msg):
    print("fs: WARN: {}".format(msg))

class FileSystem:
    def __init__(self, base_dir=os.getcwd() + '/fs/', fsid=None):
        self.handle = {}
        if fsid:
            self.id = fsid
        else:
            self.id = "{}-{}".format(int(time.time()), ''.join(random.SystemRandom().sample(string.ascii_letters, 8)))
        suffix = "/{}/".format(self.id)
        self.base_dir = os.path.abspath(base_dir) + suffix
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)

    def __del__(self):
        ### Close open files
        for path in self.handle.keys():
            self.close(path)

        # self.clean()

    ### TODO: __repr__(self)

    # @return real path
    def path(self, path):
        return self.base_dir + path
    
    def create(self, path, data):
        assert(isinstance(data, bytes))
        path_dir = os.path.dirname(self.path(path))
        if not os.path.exists(path_dir):
            os.mkdir(path_dir)
        with open(self.base_dir + path, "wb") as f:
            f.write(data)
        return self.open(path)
    
    def remove(self, path):
        if path in self.handle:
            del(self.handle[path])
        if os.path.exists(self.path(path)):
            os.remove(self.path(path))
        else:
            WARN("path '{}' does not exists")

    def clean(self):
        if self.base_dir != os.getcwd() and '/fs-' in self.base_dir:
            shutil.rmtree(self.base_dir)
            os.remove(self.base_dir)

    def open(self, path, flags='rb'):
        if not path in self.handle:
            try:
                self.handle[path] = open(self.path(path), flags)
            except FileNotFoundError:
                raise FileSystemException("fs.open: path '{}' does not exists".format(path))
        return self.attach(path)

    def attach(self, path):
        if path in self.handle:
            return self.handle[path]
        else:
            raise FileSystemException("fs.attach: path '{}' is not opened".format(path))

    def close(self, path):
        f = self.handle[path]
        del self.handle[path]
        return f.close()

if __name__ == "__main__":
    fs = FileSystem('fs-test')
    fs.create('hello', b'google')
    f = fs.open('hello')
    print(fs.base_dir + 'hello')
    assert(os.path.exists(fs.base_dir + 'hello') == True)
    data = f.read()
    print(data)
    assert(data == 'google')
    fs.remove('hello')
    assert(os.path.exists(fs.base_dir + 'hello') == False)

    print(fs.handle)

    import subprocess
    fs.create('hello2', b'google!!')
    f = fs.open('hello2')
    p = subprocess.Popen(['/bin/cat'], stdin=f, stdout=subprocess.PIPE)
    stdout, _ = p.communicate()
    print(stdout)

    # fs.clean()