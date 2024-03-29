from collections import defaultdict
from util import UNDEF_ADDR, CFuncGraph, GraphBuilder, hexrays_vars, get_expr_name
import idaapi
import ida_hexrays
import ida_kernwin
import ida_pro
import json
import jsonlines
import os
import re

# Dictionary mapping variable ids to (orig, orig) pairs
varnames = dict()
var_id = 0
sentinel_vars = re.compile('@@VAR_[0-9]+')

class RenamedGraphBuilder(GraphBuilder):
    def __init__(self, cg, func):
        self.func = func
        super(RenamedGraphBuilder, self).__init__(cg)

    def visit_expr(self, e):
        global var_id
        if e.op is ida_hexrays.cot_var:
            # Save original name of variable
            original_name = get_expr_name(e)
            if not sentinel_vars.match(original_name):
                # Save names
                varnames[var_id] = (original_name, original_name)
                # Rename variables to @@VAR_[id]@@[orig name]@@[orig name]
                self.func.get_lvars()[e.v.idx].name = \
                    '@@VAR_' + str(var_id) + '@@' + original_name + '@@' + original_name
                var_id += 1
        return self.process(e)

class AddressCollector:
    def __init__(self, cg):
        self.cg = cg
        self.addresses = defaultdict(set)

    def collect(self):
        for item in self.cg.items:
            if item.op is ida_hexrays.cot_var:
                name = get_expr_name(item)
                if item.ea != UNDEF_ADDR:
                    self.addresses[name].add(item.ea)
                else:
                    item_id = next(b for a, b in self.cg.reverse if a == item)
                    ea = self.cg.get_pred_ea(item_id)
                    if ea != UNDEF_ADDR:
                        self.addresses[name].add(ea)

# Process a single function given its EA
def func(ea):
    f = idaapi.get_func(ea)
    if hasattr(idaapi, "GetFunctionName"):
        function_name = GetFunctionName(ea)
    else:
        function_name = get_func_name(ea)
    if f is None:
        print('Please position the cursor within a function')

    cfunc = None
    try:
        cfunc = idaapi.decompile(f)
    except ida_hexrays.DecompilationFailure as e:
        print('Failed to decompile %x: %s!' % (ea, function_name))
        raise e

    renamed_file = renamed_prefix + '_' + function_name + '.c'

    # Rename decompilation graph
    cg = CFuncGraph(None)
    gb = GraphBuilder(cg)
    gb.apply_to(cfunc.body, None)
    ac = AddressCollector(cg)
    ac.collect()
    rg = RenamedGraphBuilder(cg, cfunc)
    rg.apply_to(cfunc.body, None)

    # Create tree from collected names
    cfunc.build_c_tree()
    new_graph = CFuncGraph(None)
    new_builder = GraphBuilder(new_graph)
    new_builder.apply_to(cfunc.body, None)
    function_info = dict()
    function_info["function"] = function_name
    function_info["ast"] = new_graph.json_tree(0)
    raw_code = ""
    for line in cfunc.get_pseudocode():
        raw_code += idaapi.tag_remove(line.line) + '\n'
    function_info["raw_code"] = raw_code
    return function_info

class custom_action_handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

class collect_vars(custom_action_handler):
    def activate(self, ctx):
        print('Collecting vars.')
        jsonl_file_name = os.path.join(os.environ['OUTPUT_DIR'],
                                       os.environ['PREFIX']) + '.jsonl'
        with open(jsonl_file_name, 'w+') as jsonl_file:
            with jsonlines.Writer(jsonl_file) as writer:
                for ea in Functions():
                    try:
                        info = func(ea)
                        writer.write(func(ea))
                    except ida_hexrays.DecompilationFailure:
                        continue
        print('Vars collected.')
        return 1

def main():
    global renamed_prefix
    global varnames
    renamed_prefix = os.path.join(os.environ['OUTPUT_DIR'], 'functions',
                                  os.environ['PREFIX'])

    # Collect decompilation info
    cv = collect_vars()
    cv.activate(None)

if hasattr(idaapi, "auto_wait"): # IDA 7.4+
    idaapi.auto_wait()
else:
    idaapi.autoWait() # Old IDA
if not idaapi.init_hexrays_plugin():
    idaapi.load_plugin('hexrays')
    idaapi.load_plugin('hexx64')
    if not idaapi.init_hexrays_plugin():
        print('Unable to load Hex-rays')
    else:
        print('Hex-rays version %s has been detected' % idaapi.get_hexrays_version())
main()
ida_pro.qexit(0)
