# from .inspector import Inspector

class BreakpointManager(object):
    def __init__(self, inspector):
        # assert isinstance(inspector, Inspector)
        self.inspector = inspector
        self.hook = {}
        self.already_set = set()

    def set_breakpoint(self, v, hook):
        inspector = self.inspector
        if not (v.addr, v.objfile) in self.already_set:
            # print("[*] BreakpointManager.set_breakpoint(): set breakpoint at {}".format(v))
            inspector.set_breakpoint(variable=v)
            self.already_set.add((v.addr, v.objfile))
        rebased_addr = inspector.get_tracee_rebased_addr(object_name=v.objfile, relative_addr=v.addr)
        if rebased_addr in self.hook:
            self.hook[rebased_addr].add(hook)
        else:
            self.hook[rebased_addr] = set([hook])

    def get_hook(self, rebased_addr):
        if rebased_addr in self.hook:
            return self.hook[rebased_addr]
        else:
            return set()