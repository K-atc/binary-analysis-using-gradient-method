import numbers
import ctypes

def yadapter(constraint, y):
    try:
        variables = constraint.get_variables()
        res = []
        for v in variables:
            try:
                value = y[v.name]
                if isinstance(value, numbers.Number): # Scalar
                    if value < 0x100000000: # 32bit int
                        value = ctypes.c_int(value).value                    
                    else: # 64bit int
                        value = ctypes.c_long(value).value
                    res.append(value)
                elif len(value) == 1: # array-like object
                    res.append(ord(value))
                else: # sage.symbolic.expression.Expression ?
                    res.append(value)
                    # raise UnhandledCaseError("v={}".format(v))
            except KeyError:
                ### NOTE: Program does not reached the block.
                if True: print("[!] yadapter(): Value of {} not found: {}".format(v.name, v))
                exit(1)
        assert len(res) == len(variables)
        return res
    except Exception as e:
        import traceback
        print("\nException: {} {}".format(e.__class__.__name__, e))
        traceback.print_exc()
        print("")
        print("-> value = {!r}".format(value))
        print("-> y = {}".format(y))
        print("-> variables = {}".format(variables))
        import ipdb; ipdb.set_trace()
        exit(1)