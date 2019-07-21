# from .inspector import Inspector
from .exceptions import UnexpectedException
from .ast.constraint import Variable 

class BreakpointManager(object):
    def __init__(self, inspector):
        # assert isinstance(inspector, Inspector)
        self.inspector = inspector
        self.hook = {}
        self.already_set = set()

    def set_breakpoint(self, hook, variable=None, object_name=None, relative_addr=None):
        assert callable(hook)
        assert variable is None or isinstance(variable, Variable)

        if variable:
            object_name = variable.objfile
            relative_addr = variable.addr
        elif object_name and relative_addr:
            pass
        else:
            raise UnexpectedException("invalid function call: set_breakpoint(variable={}, object_name={}, relative_addr={})".format(variable))

        ### Set breakpoint
        if not (object_name, relative_addr) in self.already_set:
            if self.inspector.debug: print("[*] inspector.set_breakpoint(object_name={}, relative_addr={:#x})".format(object_name, relative_addr))
            self.inspector.set_breakpoint(object_name=object_name, relative_addr=relative_addr)
            self.already_set.add((object_name, relative_addr))
        
        ### Add hook
        rebased_addr = self.inspector.get_tracee_rebased_addr(object_name=object_name, relative_addr=relative_addr)
        if rebased_addr in self.hook:
            self.hook[rebased_addr].add(hook)
        else:
            self.hook[rebased_addr] = set([hook])

    def get_hook(self, rebased_addr):
        if rebased_addr in self.hook:
            return self.hook[rebased_addr]
        else:
            return set()