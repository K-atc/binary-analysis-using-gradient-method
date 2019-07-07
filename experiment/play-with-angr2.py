import angr
from nao.util import Inspector, Tactic

inspector = Inspector("./sample/ais3_crackme", debug=True)
find_addr = 0x40061D

cond = inspector.get_condition_at(Tactic.near_path_constraint, rebased_addr=find_addr)
print("post condition = {}".format(cond))