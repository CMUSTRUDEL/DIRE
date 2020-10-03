from collections import defaultdict
from util import UNDEF_ADDR, CFuncGraph, GraphBuilder, hexrays_vars, get_expr_name
import idaapi
import ida_hexrays
import json
import jsonlines
import os
import re
import subprocess
import sys

try:
    from CStringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

# Dictionary mapping variable ids to (orig, orig) pairs
varnames = dict()
oldvarnames = dict()
var_id = 0
sentinel_vars = re.compile('@@VAR_[0-9]+')

actname = "predict:varnames"

dire_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..', '..'))
MODEL = os.path.join(dire_dir, 'data', 'saved_models', 'model.hybrid.bin')

# Rename variables to sentinel representation
class RenamedGraphBuilder(GraphBuilder):
    def __init__(self, cg, func, vuu):
        self.func = func
        self.vuu = vuu
        super(RenamedGraphBuilder, self).__init__(cg)

    def visit_expr(self, e):
        global var_id
        if e.op is ida_hexrays.cot_var:
            # Save original name of variable
            original_name = get_expr_name(e)
            if not sentinel_vars.match(original_name):
                # Rename variables to @@VAR_[id]@@[orig name]@@[orig name]
                new_name = '@@VAR_' + str(var_id) + '@@' + original_name + '@@' + original_name
                self.vuu.rename_lvar(self.vuu.cfunc.get_lvars()[e.v.idx],
                                     str(new_name),
                                     True)
                # This is needed so that the NN graph sees the new
                # name without visiting the entire expression again.
                self.func.get_lvars()[e.v.idx].name = str(new_name)
                varnames[original_name] = new_name
                oldvarnames[new_name] = original_name
                var_id += 1
        return self.process(e)

# Rename variables to predicted names
class FinalRename(ida_hexrays.ctree_visitor_t):
    def __init__(self, renamings, func, vuu):
        super(FinalRename, self).__init__(0)
        self.renamings = renamings
        self.func = func
        self.vuu = vuu

    def visit_expr(self, e):
        if e.op is ida_hexrays.cot_var:
            original_name = get_expr_name(e)
            if original_name in self.renamings:
                new_name = self.renamings[original_name]

                if oldvarnames[original_name] != new_name:
                    print("Renaming %s to %s"%(oldvarnames[original_name],new_name))
                # This one refreshes the pseudo-code window
                self.vuu.rename_lvar(self.vuu.cfunc.get_lvars()[e.v.idx],
                                str(new_name),
                                True)
                # This one stops us from renaming the same variable
                # over and over. Otherwise it's not needed.
                self.func.get_lvars()[e.v.idx].name = str(new_name)
        return 0

# Process a single function given its EA
def func(ea, vuu):
    f = idaapi.get_func(ea)
    function_name = idaapi.get_func_name(ea)
    if f is None:
        print('Please position the cursor within a function')

    cfunc = None
    try:
        cfunc = idaapi.decompile(f)
    except ida_hexrays.DecompilationFailure as e:
        print('Failed to decompile %x: %s!' % (ea, function_name))
        raise e

    # Rename decompilation graph
    cg = CFuncGraph(None)
    gb = GraphBuilder(cg)
    gb.apply_to(cfunc.body, None)
    #ac = AddressCollector(cg)
    #ac.collect()
    rg = RenamedGraphBuilder(cg, cfunc, vuu)
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
    return function_info, cfunc

class predict_names_ah_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("Suggesting variable names...")
        idaapi.show_wait_box("Suggesting variable names... please wait")
        ea = idaapi.get_screen_ea()
        vuu = ida_hexrays.get_widget_vdui(ctx.widget)
        if ea is None:
            idaapi.warning("Current function not found.")
        else:
            f = StringIO()
            with jsonlines.Writer(f) as writer:
                try:
                    info, cfunc = func(ea, vuu)
                    # We must set the working directory to the dire dir to open the model correctly
                    os.chdir(dire_dir)
                    p = subprocess.Popen(['python', '-m', 'DIRE.prediction_plugin.run_one', '--model', MODEL], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, encoding=sys.getdefaultencoding())
                    #print(info)
                    writer.write(info)
                    comm = p.communicate(input=f.getvalue())
                    json_results = comm[0]
                    stderr = comm[1]
                    if p.returncode != 0:
                        print(stderr)
                        raise ValueError("Variable prediction failed")
                    results = json.loads(json_results)
                    best_results = results[0][0]
                    #print("best: ", best_results)
                    tuples = map(lambda x: (varnames[x[0]] if x[0] in varnames else x[0], x[1]['new_name']), best_results.items())

                    FinalRename(dict(tuples), cfunc, vuu).apply_to(cfunc.body, None)

                    # Force the UI to update
                    #vuu.refresh_ctext()

                except ida_hexrays.DecompilationFailure:
                    idaapi.warning("Decompilation failed")

                except ValueError as e:
                    idaapi.warning(str(e) + ". See output window for more details.")

        idaapi.hide_wait_box()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == idaapi.BWN_PSEUDOCODE else \
            idaapi.AST_DISABLE_FOR_WIDGET

class name_hooks_t(idaapi.Hexrays_Hooks):
    def __init__(self):
        idaapi.Hexrays_Hooks.__init__(self)
    def populating_popup(self, widget, phandle, vu):
        idaapi.attach_action_to_popup(vu.ct, None, actname)
        return 0

if idaapi.init_hexrays_plugin():
    idaapi.register_action(
        idaapi.action_desc_t(
            actname,
            "Predict variable names",
            predict_names_ah_t(),
            "P"))
    name_hooks = name_hooks_t()
    name_hooks.hook()
else:
    print('Predict variable names: hexrays is not available.')

class plugin(idaapi.plugin_t):
    flags = 0
    comment = "Predicts variable names in decompiled code"

    wanted_name = "Predict variable names"
    #wanted_hotkey = "P"

    def init(self):
        return idaapi.PLUGIN_KEEP

def PLUGIN_ENTRY():
    return plugin()
