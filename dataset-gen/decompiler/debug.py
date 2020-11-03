import os
import pickle

import idaapi as ida
from idautils import Functions

from ida_lines import tag_remove

from collect import Collector
from function import Function
from dire_types import TypeLib


class CollectDebug(Collector):
    """Class for collecting debug information"""

    def __init__(self):
        self.functions: Dict[int, Function] = dict()
        super().__init__()

    def write_functions(self) -> None:
        """Dumps the collected functions to the file specified by the environment
        variable `FUNCTIONS`.
        """
        with open(os.environ["FUNCTIONS"], "wb") as functions_fh:
            pickle.dump(self.functions, functions_fh)
            functions_fh.flush()

    def activate(self, ctx) -> int:
        """Collects types, user-defined variables, and their locations"""
        print("Collecting vars and types.")
        # `ea` is the start address of a single function
        for ea in Functions():
            # Decompile
            f = ida.get_func(ea)
            cfunc = None
            try:
                cfunc = ida.decompile(f)
            except ida.DecompilationFailure:
                continue
            if cfunc is None:
                continue

            # Function info
            name: str = ida.get_func_name(ea)
            self.type_lib.add_ida_type(cfunc.type.get_rettype())
            return_type = TypeLib.parse_ida_type(cfunc.type.get_rettype())

            arguments = self.collect_variables(
                f.frsize, cfunc.get_stkoff_delta(), cfunc.arguments
            )
            local_vars = self.collect_variables(
                f.frsize,
                cfunc.get_stkoff_delta(),
                [v for v in cfunc.get_lvars() if not v.is_arg_var],
            )
            raw_code = ""
            for line in cfunc.get_pseudocode():
                raw_code += f"{' '.join(tag_remove(line.line).split())}\n"
            self.functions[ea] = Function(
                name=name,
                return_type=return_type,
                arguments=arguments,
                local_vars=local_vars,
                raw_code=raw_code,
            )

        self.write_type_lib()
        self.write_functions()
        return 1


ida.auto_wait()
if not ida.init_hexrays_plugin():
    ida.load_plugin("hexrays")
    ida.load_plugin("hexx64")
    if not ida.init_hexrays_plugin():
        print("Unable to load Hex-rays")
        ida.qexit(1)
    else:
        print(f"Hex-rays version {ida.get_hexrays_version()}")

debug = CollectDebug()
debug.activate(None)
ida.qexit(0)
