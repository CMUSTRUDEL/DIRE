import gzip
import idaapi as ida
from idautils import Functions
import pickle
import os

from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, List, Optional, Set

from function import Function
from dire_types import Padding, TypeInfo, TypeLib, TypeLibCodec
from variable import Location, Stack, Register, Variable


class Collector(ida.action_handler_t):
    """Generic class to collect information from a binary"""

    def __init__(self):
        # Load the type library
        self.type_lib_file_name = os.path.join(
            os.environ["OUTPUT_DIR"],
            "types",
            os.environ["PREFIX"] + ".json.gz",
        )
        try:
            with gzip.open(self.type_lib_file_name, "rt") as type_lib_file:
                self.type_lib = TypeLibCodec.decode(type_lib_file.read())
        except Exception as e:
            print(e)
            print("Could not find type library, creating a new one")
            self.type_lib = TypeLib()
        super().__init__()

    def write_type_lib(self) -> None:
        """Dumps the type library to the file specified by the environment variable
        `TYPE_LIB`.
        """
        with gzip.open(self.type_lib_file_name, "wt") as type_lib_file:
            encoded = TypeLibCodec.encode(self.type_lib)
            type_lib_file.write(encoded)
            type_lib_file.flush()

    def collect_variables(
        self,
        frsize: int,
        stkoff_delta: int,
        variables: Iterable[ida.lvar_t],
    ) -> DefaultDict[Location, Set[Variable]]:
        """Collects Variables from a list of tinfo_ts and adds their types to the type
        library."""
        collected_vars: DefaultDict[Location, Set[Variable]] = defaultdict(set)

        # Filter out variables with no name or type
        variables = [v for v in variables if v.name != "" and v.type() is not None]

        # The list of start offsets of the stack variables. Used to compute
        # padding between variables on the stack.
        offsets: List[int] = []
        for v in variables:
            # Add all types to the typelib
            self.type_lib.add_ida_type(v.type())
            if v.is_stk_var():
                corrected = v.get_stkoff() - stkoff_delta
                offsets.append(frsize - corrected)

        # Compute the distance between each (unique) offset and the one
        # following it, this will be used to compute the padding.
        dist = dict()
        seen = set()
        filtered_offsets = []
        for o in offsets:
            if o not in seen:
                filtered_offsets.append(o)
            seen.add(o)

        if filtered_offsets != []:
            dist[filtered_offsets[-1]] = 0
            prev = filtered_offsets[0]
            for cur in filtered_offsets[1:]:
                dist[prev] = prev - cur
                prev = cur

        # Dict of locations that need padding. This maps the offset of the
        # previous location to a (padding_location, padding_size) tuple
        padding_to_add = dict()

        for v in variables:
            loc = None
            if v.is_stk_var():
                # If this is a stack variable, get its start offset and
                # check if there is padding. If there is, add it to the
                # collected vars.
                offset = offsets.pop(0)
                loc = Stack(offset)

                typ = TypeLib.parse_ida_type(v.type())
                # Check if the size of the type is the same as the amount of space.
                if offsets != [] and offset - offsets[0] - typ.size > 0:
                    padding_size = offset - offsets[0] - typ.size
                    padding_location = offset - typ.size
                    # Add the minimum amount of padding seen at this location
                    if offset in padding_to_add:
                        _, prev_size = padding_to_add[offset]
                        if padding_size < prev_size:
                            padding_to_add[offset] = (padding_location, padding_size)
                    else:
                        padding_to_add[offset] = (padding_location, padding_size)
                else:
                    # If we don't need padding here, make sure to zero it out
                    padding_to_add[offset] = (offset, 0)
            if v.is_reg_var():
                loc = Register(v.get_reg1())
                typ = TypeLib.parse_ida_type(v.type())

            if loc is not None:
                collected_vars[loc].add(
                    Variable(typ=typ, name=v.name, user=v.has_user_info)
                )

        # Add all the padding.
        for loc, size in padding_to_add.values():
            if size > 0:
                padding = Padding(size)
                padding_loc = Stack(loc)
                collected_vars[padding_loc].add(Variable(typ=padding))

        return collected_vars

    def activate(self, ctx) -> int:
        """Runs the collector"""
        raise NotImplementedError
