import os
import shutil

class FileSystemException(Exception):
    pass

def WARN(msg):
    print("fs: WARN: {}".format(msg))

class FileSystem:
    def __init__(self, base_dir=os.getcwd() + '/fs/'):
        self.handle = {}
        self.base_dir = os.path.abspath(base_dir) + os.sep
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)

    def __del__(self):
        # self.clean()

        ### Close open files
        for path in self.handle.keys():
            self.close(path)
    
    def create(self, path, data):
        assert(isinstance(data, bytes))
        path_dir = os.path.dirname(self.base_dir + path)
        if not os.path.exists(path_dir):
            os.mkdir(path_dir)
        with open(self.base_dir + path, "wb") as f:
            f.write(data)
        return None
    
    def remove(self, path):
        if path in self.handle:
            del(self.handle[path])
        if os.path.exists(self.base_dir + path):
            os.remove(self.base_dir + path)
        else:
            WARN("path '{}' does not exists")

    def clean(self):
        if self.base_dir != os.getcwd():
            shutil.rmtree(self.base_dir)

    def open(self, path, flags='rb'):
        if not path in self.handle:
            try:
                self.handle[path] = open(self.base_dir + path, flags)
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