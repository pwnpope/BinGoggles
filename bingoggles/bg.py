from binaryninja.variable import Variable
from binaryninja.mediumlevelil import (
    MediumLevelILVar,
    MediumLevelILRet,
    MediumLevelILVarSsa,
)
from binaryninja.highlevelil import HighLevelILOperation
from binaryninja import Function
from binaryninja.enums import SymbolType
from functools import cache
from colorama import Fore

from .bingoggles_types import *
from .auxiliary import *
from binaryninja.enums import MediumLevelILOperation
from binaryninja import BinaryView
from collections import OrderedDict
from typing import List, Union
from .function_registry import get_modeled_function_index, modeled_functions


class Analysis:
    def __init__(
        self,
        binaryview: BinaryView,
        verbose: bool = False,
        libraries_mapped: dict = None,
    ):
        """
        Performs interprocedural taint and variable flow analysis using Binary Ninja's IL representations.

        The `Analysis` class serves as the central engine for BinGoggles. It provides both intra-procedural and inter-procedural
        variable taint propagation capabilities across variables, struct members, globals, and imported functions.

        It supports full-function taint tracing, cross-function taint mapping (calls and returns), and custom modeling of
        common library calls. This enables use cases such as:

            - Detecting if a return value is influenced by a tainted parameter
            - Tracing variable flows through dereferences, field offsets, or across stack frames
            - Analyzing modeled/builtin/imported library calls for known behavior
            - Producing forward/backward slices on variables, globals, or struct members

        Attributes:
            bv (BinaryView): The Binary Ninja view object for the binary under analysis.
            verbose (bool): Enables verbose logging output.
            libraries_mapped (dict): Optional dictionary of mapped library views for imported function analysis.
            glob_refs_memoized (dict): Memoized cache for global references (used internally).

        Methods:
            - tainted_slice(...): Produce a forward/backward intra-procedural slice.
            - complete_slice(...): Perform interprocedural taint propagation across function calls.
            - trace_function_taint(...): Analyze a function to determine if taint propagates to return or other params.
            - get_sliced_calls(...): Extract tainted function calls from a taint slice.
            - find_first_var_use(...): Find first instruction where a variable is read or written in SSA form.
            - resolve_function_type(...): Classify a call destination as imported, builtin, or neither.
            - analyze_function_taint(...): Analyze imported or modeled functions for taint propagation.
        """
        self.bv = binaryview
        self.verbose = verbose
        self.libraries_mapped = libraries_mapped
        self.glob_refs_memoized = {}

        if self.verbose:
            self.trace_function_taint_printed = False

    @cache
    def get_sliced_calls(
        self,
        data: List[TaintedLOC],
        func_name: str,
        propagated_vars: List[
            Union[TaintedVar, TaintedGlobal, TaintedVarOffset, TaintedStructMember]
        ],
    ) -> dict | None:
        """
        Identify and extract function calls within a tainted slice, along with their metadata.

        This method scans through a list of tainted locations (TaintedLOC) and collects all
        MLIL function call instructions where any of the arguments match propagated tainted variables.
        For each call, it attempts to resolve the destination function and builds a parameter map
        of tainted arguments.

        Args:
            data (List[TaintedLOC]): The list of locations visited during the taint slice.
            func_name (str): The name of the function being analyzed.
            propagated_vars (List[Union[TaintedVar, TaintedGlobal, TaintedVarOffset, TaintedStructMember]]):
                The list of tainted variables that were propagated during the slice.

        Returns:
            dict | None: A dictionary mapping `(func_name, call_addr)` tuples to a tuple containing:
                - The resolved call target's name (`str`)
                - The target function's start address (`int`)
                - The MLIL call instruction (`MediumLevelILInstruction`)
                - A dictionary of argument indices to their tainted variable matches (`dict`)
            Returns `None` if no matching calls are found.
        """
        if self.verbose:
            print(
                f"\n{Fore.LIGHTRED_EX}get_sliced_calls{Fore.RESET}({Fore.MAGENTA}self, data: list, func_name: str, verbose: list{Fore.RESET})\n{f'{Fore.GREEN}={Fore.RESET}' * 65}"
            )

        function_calls = {}

        for taintedloc in data:
            addr = taintedloc.addr
            loc = taintedloc.loc

            if int(loc.operation) == int(MediumLevelILOperation.MLIL_CALL):
                param_map = param_var_map(loc.params, propagated_vars)
                call_function_object = addr_to_func(self.bv, int(str(loc.dest), 16))
                if call_function_object:
                    function_addr = call_function_object.start
                    call_name = call_function_object.name

                else:
                    continue

                key = (func_name, addr)

                if self.verbose:
                    print(
                        f"({key[0]}, {key[1]:#0x}): {call_name}, {function_addr:#0x}, {loc}, {param_map}"
                    )

                function_calls[key] = (
                    call_name,
                    function_addr,
                    loc,
                    param_map,
                )

        return function_calls

    @cache
    def tainted_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        output: OutputMode = OutputMode.Returned,
        slice_type: SliceType = SliceType.Forward,
    ) -> Union[tuple[list, str, list[Variable]], None]:
        """
        Perform a taint analysis slice (forward or backward) from a specified target variable.

        This function identifies and traces the propagation of a variable (local, global,
        struct member, or function parameter) through a function using either forward or
        backward slicing. It returns a list of program locations affected by the variable
        and a list of propagated variables.

        Args:
            target (TaintTarget): The target variable to slice from, including its name and location.
            var_type (SlicingID): The classification of the target variable
                (FunctionVar, GlobalVar, StructMember, or FunctionParam).
            output (OutputMode, optional): Whether to print the slice results or return them.
                Defaults to OutputMode.Returned.
            slice_type (SliceType, optional): Direction of the slice (Forward or Backward).
                Defaults to SliceType.Forward.

        Returns:
            tuple[list, str, list[Variable]] | None:
                - A list of `TaintedLOC` objects representing the instructions visited during the slice.
                - The name of the function containing the slice.
                - A list of variables propagated during the slice.
                Returns `None` if the analysis fails due to unresolved instruction or function context.
        """
        if hasattr(target.loc_address, "start"):
            func_obj = target.loc_address

        else:
            func_obj = addr_to_func(self.bv, target.loc_address)
            if func_obj is None:
                print(
                    f"[{Fore.RED}Error{Fore.RESET}] Could not find a function containing address: {target.loc_address}"
                )
                return None

        sliced_func = {}
        propagated_vars = []

        instr_mlil = None
        if var_type != SlicingID.FunctionParam:
            instr_mlil = func_obj.get_llil_at(target.loc_address).mlil
            if instr_mlil is None:
                raise AttributeError(
                    f"[{Fore.RED}Error{Fore.RESET}] The address you provided for the target variable is likely wrong."
                )

        # Start by tracing the initial target variable
        match var_type:
            # Handle case where the target var for slicing is a function var
            case SlicingID.FunctionVar:
                var_object = str_to_var_object(target.variable, func_obj)

                if var_object:
                    # Handle regular variables
                    if slice_type == SliceType.Forward:
                        sliced_func, propagated_vars = trace_tainted_variable(
                            analysis=self,
                            function_object=func_obj,
                            mlil_loc=instr_mlil,
                            variable=var_object,
                            trace_type=SliceType.Forward,
                        )

                    elif slice_type == SliceType.Backward:
                        sliced_func, propagated_vars = trace_tainted_variable(
                            analysis=self,
                            function_object=func_obj,
                            mlil_loc=instr_mlil,
                            variable=var_object,
                            trace_type=SliceType.Backward,
                        )

                    else:
                        raise TypeError(
                            f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                        )

            case SlicingID.GlobalVar:
                # Handle Globals
                symbol = [
                    s
                    for s in self.bv.get_symbols()
                    if int(s.type) == int(SymbolType.DataSymbol)
                    and s.name == target.variable
                ]
                if symbol:
                    constr_ptr = None

                    for op in flat(instr_mlil.operands):
                        if hasattr(op, "address"):
                            s = get_symbol_from_const_ptr(self.bv, op)
                            if s and s == symbol:
                                constr_ptr = op
                                break

                    tainted_global = TaintedGlobal(
                        variable=target.variable,
                        confidence_level=TaintConfidence.Tainted,
                        loc_address=target.loc_address,
                        const_ptr=constr_ptr,
                        symbol_object=symbol,
                    )

                    if slice_type == SliceType.Forward:
                        sliced_func, propagated_vars = trace_tainted_variable(
                            analysis=self,
                            function_object=func_obj,
                            mlil_loc=instr_mlil,
                            variable=tainted_global,
                            trace_type=SliceType.Forward,
                        )

                    elif slice_type == SliceType.Backward:
                        sliced_func, propagated_vars = trace_tainted_variable(
                            analysis=self,
                            function_object=func_obj,
                            mlil_loc=instr_mlil,
                            variable=tainted_global,
                            trace_type=SliceType.Backward,
                        )

                    else:
                        raise TypeError(
                            f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                        )

            case SlicingID.StructMember:
                # Handle struct member references/derefernces
                instr_hlil = func_obj.get_llil_at(target.loc_address).hlil

                try:
                    struct_offset = instr_mlil.ssa_form.src.offset
                except AttributeError:
                    struct_offset = instr_mlil.ssa_form.offset

                if instr_hlil.operation == int(HighLevelILOperation.HLIL_ASSIGN):
                    destination = instr_hlil.dest

                    if destination.operation == int(
                        HighLevelILOperation.HLIL_DEREF_FIELD
                    ):
                        struct_offset = destination.offset
                        base_expr = destination.src

                        if base_expr.operation == int(HighLevelILOperation.HLIL_VAR):
                            base_var = base_expr.var
                            tainted_struct_member = TaintedStructMember(
                                loc_address=target.loc_address,
                                member=target.variable,
                                offset=struct_offset,
                                hlil_var=base_var,
                                variable=instr_mlil.dest.var,
                                confidence_level=TaintConfidence.Tainted,
                            )

                            if slice_type == SliceType.Forward:
                                sliced_func, propagated_vars = trace_tainted_variable(
                                    analysis=self,
                                    function_object=func_obj,
                                    mlil_loc=instr_mlil,
                                    variable=tainted_struct_member,
                                    trace_type=SliceType.Forward,
                                )

                            elif slice_type == SliceType.Backward:
                                sliced_func, propagated_vars = trace_tainted_variable(
                                    analysis=self,
                                    function_object=func_obj,
                                    mlil_loc=instr_mlil,
                                    variable=tainted_struct_member,
                                    trace_type=SliceType.Backward,
                                )

                            else:
                                raise TypeError(
                                    f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                                )

                elif instr_mlil.operation == int(MediumLevelILOperation.MLIL_SET_VAR):
                    source = instr_mlil.src
                    base_var = instr_mlil.src.src
                    if source.operation == int(MediumLevelILOperation.MLIL_LOAD_STRUCT):
                        tainted_struct_member = TaintedStructMember(
                            loc_address=target.loc_address,
                            member=target.variable,
                            offset=struct_offset,
                            hlil_var=base_var,
                            variable=instr_mlil.src.src.var,
                            confidence_level=TaintConfidence.Tainted,
                        )

                        if slice_type == SliceType.Forward:
                            sliced_func, propagated_vars = trace_tainted_variable(
                                analysis=self,
                                function_object=func_obj,
                                mlil_loc=instr_mlil,
                                variable=tainted_struct_member,
                                trace_type=SliceType.Forward,
                            )

                        elif slice_type == SliceType.Backward:
                            sliced_func, propagated_vars = trace_tainted_variable(
                                analysis=self,
                                function_object=func_obj,
                                mlil_loc=instr_mlil,
                                variable=tainted_struct_member,
                                trace_type=SliceType.Backward,
                            )

                        else:
                            raise TypeError(
                                f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                            )

                    elif source.operation == int(MediumLevelILOperation.MLIL_VAR_FIELD):
                        tainted_struct_member = TaintedStructMember(
                            loc_address=target.loc_address,
                            member=target.variable,
                            offset=struct_offset,
                            hlil_var=base_var,
                            variable=instr_mlil.dest,
                            confidence_level=TaintConfidence.Tainted,
                        )

                        if slice_type == SliceType.Forward:
                            sliced_func, propagated_vars = trace_tainted_variable(
                                analysis=self,
                                function_object=func_obj,
                                mlil_loc=instr_mlil,
                                variable=tainted_struct_member,
                                trace_type=SliceType.Forward,
                            )

                        elif slice_type == SliceType.Backward:
                            sliced_func, propagated_vars = trace_tainted_variable(
                                analysis=self,
                                function_object=func_obj,
                                mlil_loc=instr_mlil,
                                variable=tainted_struct_member,
                                trace_type=SliceType.Backward,
                            )

                else:
                    raise ValueError(
                        f"[{Fore.RED}ERORR{Fore.RESET}]Couldn't find variable reference, insure that you're using the MLIL to identify your target variable"
                    )

            # In cases for function params they dont need to be used anywhere where a variable is being assigned for the first time or whatever
            # so we handle it differently than a normal variable, then can simply be passed into lines of code of function calls.
            case SlicingID.FunctionParam:
                if isinstance(target.variable, str):
                    target_param = find_param_by_name(
                        func_obj=func_obj, param_name=target.variable
                    )

                elif isinstance(target.variable, MediumLevelILVar):
                    target_param = target.variable.var

                else:
                    target_param = find_param_by_name(
                        func_obj=func_obj, param_name=target.variable.name
                    )

                try:
                    param_refs = func_obj.get_mlil_var_refs(target_param)

                except AttributeError:
                    raise AttributeError(
                        f"[{Fore.RED}Error{Fore.RESET}] Couldn't find the parameter reference"
                    )

                first_ref_addr = [
                    i.address
                    for i in param_refs
                    if func_obj.get_llil_at(i.address).mlil is not None
                ][0]

                first_ref_mlil = func_obj.get_llil_at(first_ref_addr).mlil
                sliced_func, propagated_vars = trace_tainted_variable(
                    analysis=self,
                    function_object=func_obj,
                    mlil_loc=first_ref_mlil,
                    variable=target_param,
                    trace_type=SliceType.Forward,
                )

            case _:
                raise TypeError(
                    f"{Fore.RED}var_type must be either SlicingID.FunctionParam or SlicingID.FunctionVar, please see the SlicingID class{Fore.RESET}"
                )

        match output:
            case OutputMode.Printed:
                print(
                    f"Address | LOC | Target Variable | Propagated Variable\n{(Fore.LIGHTGREEN_EX+'-'+Fore.RESET)*53}"
                )

                for _, data in sorted(sliced_func.items(), key=lambda item: item[0]):
                    for d in data:
                        print(d.loc.instr_index, d)

            case OutputMode.Returned:
                if self.verbose:
                    print(
                        f"Address | LOC | Target Variable | Propagated Variable | Taint Confidence\n{(Fore.LIGHTGREEN_EX+'-'+Fore.RESET)*72}"
                    )
                    for i in sliced_func:
                        print(i.loc.instr_index, i)

                return (
                    [
                        i for i in sliced_func
                    ],  # list of the collected loc as TaintedLOC objects
                    func_obj.name,  # Target function name
                    propagated_vars,  # List of the propagated variables as TaintedVar objects
                )

            case _:
                raise TypeError(
                    f"[{Fore.RED}ERROR{Fore.RESET}]output_mode must be either OutputMode.Printed or OutputMode.Returned"
                )

    @cache
    def complete_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        slice_type: SliceType = SliceType.Forward,
        output: OutputMode = OutputMode.Returned,
        analyze_imported_functions=False,
    ) -> OrderedDict:
        """
        Perform a complete interprocedural taint slice, recursively tracking taint propagation across function calls.

        Starting from the given taint target (a function variable or parameter), this method traces how taint spreads
        through MLIL instructions and across function boundaries where tainted values are passed as arguments.
        The slice forms a call graph-like structure showing the path of taint propagation.

        Args:
            target (TaintTarget): Starting point of the taint slice (address and variable).
            var_type (SlicingID): Type of the target (FunctionVar or FunctionParam).
            slice_type (SliceType, optional): Direction of slicing: Forward or Backward. Defaults to Forward.
            output (OutputMode, optional): Whether to return or print results. Defaults to Returned.
            analyze_imported_functions (bool, optional): Whether to recurse into imported functions. Defaults to False.

        Returns:
            OrderedDict: Maps (function_name, variable) to (tainted_locations, propagated_vars), e.g.:

                {
                    ("deeper_function", rdi): ([TaintedLOC, ...], [TaintedVar, ...]),
                    ...
                }
        """
        propagation_cache = (
            OrderedDict()
        )  # Stores final result of taint propagation per function+variable
        visited = (
            set()
        )  # Prevents infinite recursion over the same (function, parameter) pair
        imported_functions = {
            s.name
            for s in self.bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
        }

        @cache
        def _recurse_slice(
            func_name: str,
            variable,
            address,
        ):
            """
            Internal recursive helper to track taint into called functions.

            Args:
                func_name (str): Name of the function to analyze.
                variable: The function parameter or variable to slice from.
                address (int): Address of the function entry or call site.
            """
            key = (func_name, variable)
            if key in propagation_cache:
                return

            func_obj = func_name_to_object(self.bv, func_name)
            if not func_obj:
                return

            # Slice the variable in this function
            target_obj = TaintTarget(address, variable)
            slice_data, func_name, propagated_vars = self.tainted_slice(
                target=target_obj,
                var_type=(
                    SlicingID.FunctionParam
                    if isinstance(variable, Variable)
                    and variable in func_obj.parameter_vars
                    else SlicingID.FunctionVar
                ),
                slice_type=slice_type,
            )

            # Store current function's slice result
            propagation_cache[key] = (slice_data, propagated_vars)

            # Get function calls that pass along tainted variables
            sliced_calls = self.get_sliced_calls(slice_data, func_name, propagated_vars)
            if sliced_calls is None:
                return

            for (caller_func, loc_addr), (
                callee_name,
                callee_addr,
                loc,
                param_map,
            ) in sliced_calls.items():
                if not analyze_imported_functions and callee_name in imported_functions:
                    continue

                for param_var, (_, arg_pos) in param_map.items():
                    param_name = getattr(param_var, "var", param_var).name
                    propagated_names = {
                        getattr(v.variable, "var", v.variable).name
                        for v in propagated_vars
                    }
                    callee_func = addr_to_func(self.bv, callee_addr)
                    try:
                        callee_param = callee_func.parameter_vars[arg_pos - 1]
                    except IndexError:
                        continue

                    recurse_key = (callee_func.name, callee_param)

                    if param_name not in propagated_names:
                        continue

                    if not callee_func:
                        continue

                    if recurse_key in visited:
                        continue

                    visited.add(recurse_key)

                    # Recurse deeper
                    _recurse_slice(callee_func.name, callee_param, callee_addr)

        # Entry point: perform initial slice
        try:
            slice_data, og_func_name, propagated_vars = self.tainted_slice(
                target=target,
                var_type=var_type,
                slice_type=slice_type,
            )
        except TypeError:
            raise TypeError(
                f"[{Fore.RED}ERROR{Fore.RESET}] Address is likely wrong in target | got: {target.loc_address:#0x} for {target.variable}"
            )

        # Add first slice to the result cache
        parent_func_obj = func_name_to_object(self.bv, og_func_name)
        key = (og_func_name, str_to_var_object(target.variable, parent_func_obj))
        propagation_cache[key] = (slice_data, propagated_vars)

        # Check for initial cross-function taint propagation
        sliced_calls = self.get_sliced_calls(slice_data, og_func_name, propagated_vars)
        if sliced_calls:
            for (caller_func, loc_addr), (
                callee_name,
                callee_addr,
                loc,
                param_map,
            ) in sliced_calls.items():
                for param_var, (_, arg_pos) in param_map.items():
                    param_name = getattr(param_var, "var", param_var).name
                    propagated_names = {
                        getattr(v.variable, "var", v.variable).name
                        for v in propagated_vars
                    }

                    if param_name not in propagated_names:
                        continue

                    callee_func = addr_to_func(self.bv, callee_addr)
                    if not callee_func:
                        continue

                    try:
                        callee_param = callee_func.parameter_vars[arg_pos - 1]
                    except IndexError:
                        continue

                    recurse_key = (callee_func.name, callee_param)
                    if recurse_key in visited:
                        continue
                    visited.add(recurse_key)

                    if (
                        not analyze_imported_functions
                        and callee_name in imported_functions
                    ):
                        continue

                    # we don't want to do a slice into the first LOC if its on a function call and the slice type is backwards
                    # because in this case we'd want to go backwards NOT into the starting loc function call
                    if (
                        target.loc_address != loc_addr
                        and slice_type != SliceType.Backward
                    ):
                        _recurse_slice(callee_func.name, callee_param, callee_addr)

        # Handle printed output, if requested
        if output == OutputMode.Printed:
            for (fn_name, var), (locs, _) in propagation_cache.items():
                print(
                    f"Function: {fn_name} | Var: {var.name if hasattr(var, 'name') else var}"
                )
                for entry in locs:
                    print(entry)

        return propagation_cache

    def find_first_var_use(self, func: Function, var_or_name) -> Union[int, None]:
        """
        Return the first MLIL instruction where the given variable is used.

        Args:
            func (Function): The Binary Ninja Function object.
            var_or_name (Variable | str): The variable to search for.

        Returns:
            MediumLevelILInstruction | None: The first MLIL instruction using the variable, or None if not found.
        """
        target_var = var_or_name
        if isinstance(var_or_name, str):
            matches = [v for v in func.mlil.ssa_form.vars if v.name == var_or_name]
            if not matches:
                return None
            target_var = matches[0]

        for block in func.mlil.ssa_form:
            for instr in block:
                if target_var in instr.vars_read or target_var in instr.vars_written:
                    return instr.address
        return None

    @cache
    def trace_function_taint(
        self,
        function_node: int | Function,
        tainted_params: Variable | str | list[Variable],
        binary_view: BinaryView = None,
        origin_function: Function = None,
        original_tainted_params: Variable | str | list[Variable] = None,
        tainted_param_map: dict = None,
        recursion_limit=8,
        sub_functions_analyzed=0,
    ) -> InterprocTaintResult:
        """
        Perform interprocedural taint analysis to determine whether any parameters or the return value
        of a function are tainted, directly or indirectly.

        Starting from one or more tainted parameters, this method analyzes the taint flow within a
        function and recursively into any functions it calls. Taint is propagated through variable
        assignments, field accesses, and calls, and the analysis tracks whether taint returns to
        the caller or spreads to other parameters.

        Args:
            function_node (int | Function): Target function for analysis, provided as either a function start address or a Binary Ninja `Function` object.
            tainted_params (Variable | str | list[Variable]): One or more parameters to treat as initially tainted. Accepts a single `Variable`, parameter name (`str`), or a list of `Variable` objects.
            binary_view (BinaryView, optional): The BinaryView context for address resolution. Defaults to `self.bv` if not explicitly provided.
            origin_function (Function, optional): Used internally to track the original entry point of the analysis.
            original_tainted_params (Variable | str | list[Variable], optional): Original tainted inputs (preserved for reporting).
            tainted_param_map (dict, optional): Maps each tainted parameter to others it influences.
            recursion_limit (int, optional): Maximum depth for recursive analysis into sub-functions. Defaults to 8.
            sub_functions_analyzed (int, optional): Tracks how deep the current recursive call chain has gone.

        Returns:
            InterprocTaintResult: A result object containing:
                - `tainted_param_names` (set[str]): Names of parameters found to be tainted.
                - `original_tainted_variables` (list[TaintedVar]): The original tainted input(s).
                - `is_return_tainted` (bool): True if the function's return value is tainted.
                - `tainted_param_map` (dict): A mapping of input parameters to any other parameters they taint.

        Raises:
            ValueError: If the provided function address cannot be resolved to a valid function.
        """
        if tainted_param_map is None:
            tainted_param_map = {}

        if binary_view is None:
            binary_view = self.bv

        def walk_variable(var_mapping: dict, key_names: set):
            """
            Recursively traverse the variable mapping to find all variables influenced by the tainted variables.

            Args:
                var_mapping (dict): A dictionary mapping variables to the set of variables they influence.
                key_names (set): A set of variable names to start the traversal from.

            Returns:
                set: A set of all variable names influenced by the initial key_names.
            """
            if not any(var in var_mapping for var in key_names):
                return set(key_names)

            new_variables = set()

            for var_name in key_names:
                if var_name in var_mapping:
                    # print("adding var to new variables: ", var_name)
                    new_variables.update(var_mapping[var_name])

                else:
                    new_variables.add(var_name)

            return walk_variable(var_mapping, new_variables)

        # Convert function_node to a Function object if it's provided as an integer address
        if isinstance(function_node, int):
            addr = function_node
            function_node = addr_to_func(binary_view, function_node)
            if function_node is None:
                raise ValueError(
                    f"[{Fore.RED}ERROR{Fore.RESET}]Could not find target function from address @ {addr:#0x}"
                )

        if origin_function is None:
            origin_function = function_node

        if original_tainted_params is None:
            original_tainted_params = tainted_params

        # Initialize a set for TaintedVar objects
        tainted_variables = set()

        def get_ssa_variable(func, var: Variable):
            if isinstance(var, SSAVariable):
                return var

            for ssa_var in func.mlil.ssa_form.vars:
                if ssa_var.var == var:
                    return ssa_var

        # Ensure tainted_params is a list for consistent processing
        if not isinstance(tainted_params, list):
            tainted_params = [get_ssa_variable(function_node, tainted_params)]

        if self.verbose and not self.trace_function_taint_printed:
            print(
                # f"\n{Fore.LIGHTRED_EX}trace_function_taint{Fore.RESET}({Fore.MAGENTA}self, function_node: int | Function, "
                f"tainted_params: Variable | str | list[Variable]{Fore.RESET})\n-> {Fore.LIGHTBLUE_EX}{function_node}"
                f"{Fore.RESET}:{Fore.BLUE}{tainted_params}{Fore.RESET}\n{Fore.GREEN}{'='*113}{Fore.RESET}"
            )
            self.trace_function_taint_printed = True

        # Convert string parameter names to Variable objects in SSA form and wrap them in TaintedVar
        for param in tainted_params:
            if isinstance(param, str):
                try:
                    var_obj = str_param_to_var_object(
                        function_node, param, ssa_form=True
                    )
                    tainted_variables.add(
                        TaintedVar(
                            var_obj,
                            TaintConfidence.Tainted,
                            self.find_first_var_use(function_node, var_obj),
                        )
                    )

                except ValueError:
                    continue

            elif isinstance(param, Variable):
                tainted_variables.add(
                    TaintedVar(
                        param,
                        TaintConfidence.Tainted,
                        self.find_first_var_use(function_node, var_obj),
                    )
                )

        variable_mapping = {}
        tainted_parameters = set()

        # Iterate through each MLIL block in the function
        for mlil_block in function_node.mlil:
            for instr in mlil_block:
                loc = instr.ssa_form

                match int(loc.operation):
                    # Handle SSA store operation by wrapping the destination variable in TaintedVar
                    case int(MediumLevelILOperation.MLIL_STORE_SSA):
                        address_variable, offset_variable = None, None
                        offset_var_taintedvar = None
                        addr_var = None
                        offset = None

                        if len(loc.dest.operands) == 1:
                            addr_var = loc.dest.operands[0]

                        elif len(loc.dest.operands) == 2:
                            address_variable, offset_variable = loc.dest.operands
                            if isinstance(offset_variable, MediumLevelILConst):
                                addr_var, offset = loc.dest.operands
                                offset_variable = None

                            elif isinstance(offset_variable, MediumLevelILVarSsa):
                                addr_var, offset_variable = loc.dest.operands
                                offset_variable = offset_variable.var

                            else:
                                addr_var, offset = address_variable.operands

                            if offset_variable:
                                offset_var_taintedvar = [
                                    var.variable
                                    for var in tainted_variables
                                    if var.variable == offset_variable
                                ]

                        if offset_var_taintedvar:
                            tainted_variables.add(
                                TaintedVarOffset(
                                    variable=addr_var,
                                    offset=offset,
                                    offset_var=TaintedVar(
                                        variable=offset_var_taintedvar[0],
                                        confidence_level=TaintConfidence.NotTainted,
                                        loc_address=loc.address,
                                    ),
                                    confidence_level=TaintConfidence.Tainted,
                                    loc_address=loc.address,
                                    targ_function=function_node,
                                )
                            )

                        elif offset_variable:
                            tainted_variables.add(
                                TaintedVarOffset(
                                    variable=addr_var,
                                    offset=offset,
                                    offset_var=TaintedVar(
                                        variable=offset_variable,
                                        confidence_level=TaintConfidence.NotTainted,
                                        loc_address=loc.address,
                                    ),
                                    confidence_level=TaintConfidence.Tainted,
                                    loc_address=loc.address,
                                    targ_function=function_node,
                                )
                            )

                        else:
                            tainted_variables.add(
                                TaintedVarOffset(
                                    variable=(
                                        addr_var
                                        if isinstance(addr_var, Variable)
                                        else addr_var
                                    ),
                                    offset=offset,
                                    offset_var=None,
                                    confidence_level=TaintConfidence.Tainted,
                                    loc_address=loc.address,
                                    targ_function=function_node,
                                )
                            )

                    # Handle SSA load operation by wrapping the source variable in TaintedVar
                    case int(MediumLevelILOperation.MLIL_SET_VAR_SSA):
                        for var in loc.vars_written:
                            tainted_variables.add(
                                TaintedVar(
                                    var,
                                    TaintConfidence.Tainted,
                                    loc.address,
                                )
                            )

                    # Check if the instruction is a function call in SSA form
                    case int(MediumLevelILOperation.MLIL_CALL_SSA):
                        # Extract the parameters involved in the call
                        call_params = [
                            param
                            for param in loc.params
                            if isinstance(param, MediumLevelILVarSsa)
                        ]

                        call_object = addr_to_func(binary_view, int(str(loc.dest), 16))

                        if self.verbose:
                            print(
                                f"[{Fore.GREEN}INFO{Fore.RESET}] Analyzing sub-function call: {call_object} for tainted parameters"
                            )

                        if not call_object:
                            continue

                        function_call_params = call_object.parameter_vars
                        zipped_params = list(zip(call_params, function_call_params))

                        # Identify sub-function parameters that are tainted by comparing the underlying variable
                        tainted_sub_params = [
                            param[1].name
                            for param in zipped_params
                            if any(
                                tv.variable == param[0].ssa_form.var
                                for tv in tainted_variables
                            )
                        ]

                        if recursion_limit < sub_functions_analyzed:
                            interproc_results = self.trace_function_taint(
                                function_node=call_object,
                                tainted_params=tainted_sub_params,
                                binary_view=binary_view,
                                origin_function=origin_function,
                                original_tainted_params=original_tainted_params,
                                tainted_param_map=tainted_param_map,
                            )

                            sub_functions_analyzed += 1

                            # Map back the tainted sub-function parameters to the current function's variables
                            tainted_sub_variables = [
                                param[0].ssa_form.var
                                for param in zipped_params
                                if param[1].name
                                in interproc_results.tainted_param_names
                            ]

                            for sub_var in tainted_sub_variables:
                                tainted_variables.add(
                                    TaintedVar(
                                        sub_var,
                                        TaintConfidence.Tainted,
                                        loc.address,
                                    )
                                )

                            for ret_var in loc.vars_written:
                                if interproc_results.is_return_tainted:
                                    tainted_variables.add(
                                        TaintedVar(
                                            ret_var,
                                            TaintConfidence.Tainted,
                                            loc.address,
                                        )
                                    )

                    case int(MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD):
                        tainted_variables.add(
                            TaintedVar(loc.dest, TaintConfidence.Tainted, loc.address)
                        )

                    case _:
                        if loc.operation not in [
                            int(MediumLevelILOperation.MLIL_RET),
                            int(MediumLevelILOperation.MLIL_GOTO),
                            int(MediumLevelILOperation.MLIL_IF),
                            int(MediumLevelILOperation.MLIL_NORET),
                            int(MediumLevelILOperation.MLIL_NORET),
                            int(MediumLevelILOperation.MLIL_SYSCALL_SSA),
                        ]:
                            continue

                # Map variables written to the variables read in the current instruction
                for var_assignment in loc.vars_written:
                    variable_mapping[var_assignment] = loc.vars_read

                # If any read variable is tainted, mark the written variables as tainted
                if any(
                    any(tv.variable == read_var for tv in tainted_variables)
                    for read_var in loc.vars_read
                ):
                    for written_var in loc.vars_written:
                        try:
                            tainted_variables.add(
                                TaintedVar(
                                    written_var,
                                    TaintConfidence.Tainted,
                                    loc.address,
                                )
                            )

                        except AttributeError:
                            glob_symbol = get_symbol_from_const_ptr(
                                binary_view, written_var
                            )
                            if glob_symbol:
                                tainted_variables.add(
                                    TaintedGlobal(
                                        glob_symbol.name,
                                        TaintConfidence.Tainted,
                                        loc.address,
                                        written_var,
                                        glob_symbol,
                                    )
                                )

        # Extract underlying variables from TaintedVar before walking the mapping.
        underlying_tainted = {tv.variable for tv in tainted_variables}
        underlying_tainted_object = {tv for tv in tainted_variables}

        # #:DEBUG
        # from pprint import pprint

        # pprint(underlying_tainted)
        # print(f"\n{'='*100}")
        # pprint(underlying_tainted_object)
        # print(f"\n{'='*100}")
        # pprint(variable_mapping)
        # print(f"\n{'='*100}")
        # pprint(tainted_variables)
        # print(f"\n{'='*100}")

        # Determine all parameters that are tainted by walking through the variable mapping.

        # tainted_parameters.update(
        #     var
        #     for var in walk_variable(variable_mapping, underlying_tainted)
        #     if var.name in [param.name for param in origin_function.parameter_vars if isinstance(param, MediumLevelILVarSsa)]
        # )

        for var in walk_variable(variable_mapping, underlying_tainted):
            if isinstance(var, MediumLevelILVarSsa):
                var = var.var

            if var.name not in [param.name for param in origin_function.parameter_vars]:
                continue

            # matching_obj = next(
            #     (tv for tv in underlying_tainted_object if tv.variable == var), None
            # )

            # if not matching_obj:
            #     print("couldn't find match: ", var)
            #     continue

            # mlil_instr = origin_function.get_llil_at(matching_obj.loc_address).mlil

            # if mlil_instr.src.operation != int(MediumLevelILOperation.MLIL_VAR) and (
            #     mlil_instr.operation not in read_write_ops
            #     or hasattr(mlil_instr, "src")
            #     and mlil_instr.src.operation not in read_write_ops
            #     or hasattr(mlil_instr, "dest")
            #     and mlil_instr.dest.operation not in read_write_ops
            # ):
            #     print("we skipped: ", var)
            #     continue

            tainted_parameters.add(var)

        if len(tainted_parameters) > 1:
            tainted_param_map[list(tainted_parameters)[0]] = list(
                set(tainted_parameters)
            )[1:]

        # Find out if return variable is tainted
        ret_variable_tainted = False

        for t_var in tainted_variables:
            loc = origin_function.get_llil_at(t_var.loc_address)
            """
                Checking variable use sites for each variable in the tainted variables set, 
                if any of them are the return variable, the return variable is tainted.
            """
            if loc:
                try:
                    var_use_sites = t_var.variable.use_sites
                except:
                    var_use_sites = t_var.variable.var.use_sites

                for use_site in var_use_sites:
                    if isinstance(use_site, MediumLevelILRet):
                        ret_variable_tainted = True

        return InterprocTaintResult(
            tainted_param_names=tainted_parameters,
            original_tainted_variables=original_tainted_params,
            is_return_tainted=ret_variable_tainted,
            tainted_param_map=tainted_param_map,
            target_function_params=origin_function.parameter_vars,
        )

    @cache
    def resolve_function_type(
        self, instr_mlil: MediumLevelILInstruction
    ) -> tuple[str, str | Symbol | None]:
        """
        Determine whether the MLIL call targets an imported function, a builtin, or neither.

        Parameters:
            instr_mlil (MediumLevelILInstruction): The MLIL call instruction to analyze.

        Returns:
            tuple[str, str | Symbol | None]:
                - A tuple (type, identifier), where:
                    - type: 'import', 'builtin', or 'none'
                    - identifier: Symbol (for imports), or function name (for builtins), or None
        """
        call_target = instr_mlil.dest

        if call_target.operation in [
            int(MediumLevelILOperation.MLIL_CONST_PTR),
            int(MediumLevelILOperation.MLIL_CONST),
        ]:
            target_addr = call_target.constant
        else:
            return None

        func = self.bv.get_function_at(int(target_addr))
        if not func:
            return None

        if func.symbol.type == SymbolType.ImportedFunctionSymbol.value:
            return func.symbol.name

        section = self.bv.get_sections_at(target_addr)
        if section:
            name = section[0].name
            if name == ".synthetic_builtins":
                return True

        return None

    @cache
    def analyze_function_taint(
        self, func_symbol: Union[Symbol, str], tainted_param: Variable
    ) -> Union[InterprocTaintResult, FunctionModel, None]:
        """
        Analyze an imported function from a mapped library to determine if a specific parameter is tainted.

        This method looks up the given function symbol in all mapped libraries, and if a matching function
        is found, performs taint analysis on it using `trace_function_taint`.

        Args:
            func_symbol (Symbol): The symbol representing the imported function to analyze.
            tainted_param (Variable): The variable or parameter to check for taint propagation.

        Returns:
            Union[InterprocTaintResult, None]: The result of the taint analysis if the function is found and analyzed,
            otherwise None.

        Notes:
            Currently this functionality for imported function analysis needs to be revised, if another function is imported in the library that's being analyzed
        """

        # functions that are already modeled (e.g: common libc functions and binja instrinsic functions)
        if isinstance(func_symbol, str) and func_symbol in [
            func.name for func in modeled_functions
        ]:
            return modeled_functions[get_modeled_function_index(func_symbol)]

        # Analyze imported function
        if self.libraries_mapped:
            for lib_name, lib_binary_view in self.libraries_mapped.items():
                for func in lib_binary_view.functions:
                    if func.name == func_symbol.name:
                        text_section = lib_binary_view.sections.get(".text")
                        for func in lib_binary_view.functions:
                            if text_section.start <= func.start < text_section.end:
                                if func_symbol.name.lower() in func.name.lower():
                                    return self.trace_function_taint(
                                        function_node=func,
                                        tainted_params=tainted_param,
                                        binary_view=lib_binary_view,
                                    )

        return None
