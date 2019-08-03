from .ast import constraint as ir

class Tactic:
    @staticmethod
    def near_path_constraint(inspector, node):
        print("[*] near_path_constraint(node={})".format(node))
        # print("node.predecessors = {}".format(node.predecessors))
        predecessors = []
        if node.predecessors:
            predecessors += node.predecessors

            # If predecessor is called function node, add function call node as predecessor
            for pnode in node.predecessors:
                print("[*] {} -> successors = {}".format(pnode, pnode.successors))
                if pnode.addr == pnode.function_address: # If p is entory node of calld function,
                    prev_node = inspector.get_prev_node(node)
                    if prev_node:
                        predecessors.append(prev_node) # add function call node as predecessor.
                        if prev_node.predecessors:
                            predecessors += prev_node.predecessors
                    break
        # import ipdb; ipdb.set_trace()

        ### NOTE: Incerrect implementation for get_prev_node()
        for pnode in node.predecessors:
            prev = inspector.get_prev_node(pnode)
            if prev:
                predecessors.append(prev)

        predecessors_conditions = ir.ConstraintList()
        predecessors = set(predecessors)
        print("[*] Tactic.near_path_constraint: predecessors = {}".format(predecessors))
        for predecessor in predecessors:
            assert predecessor is not None
            if predecessor.is_simprocedure: # skip symbolic procedure (simprocedure is introduced by angr)
                continue
            jumps_on_branch = False
            if len(predecessor.successors) == 2: # Conditional Branch
                # import ipdb; ipdb.set_trace()
                if predecessor.addr + predecessor.size == node.addr: # takes no jump (sequential nodes)
                    jumps_on_branch = False
                else:
                    jumps_on_branch = True
            predecessor_condition = inspector.get_node_condition(predecessor, jumps_on_branch)
            if predecessor_condition != ir.Top():
                predecessors_conditions += predecessor_condition
        return predecessors_conditions