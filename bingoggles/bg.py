from binaryninja.variable import Variable
from binaryninja.mediumlevelil import (
    MediumLevelILVar,
    MediumLevelILRet,
    MediumLevelILVarSsa,
    MediumLevelILInstruction,
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
from binaryninja.mediumlevelil import MediumLevelILCall
from collections import OrderedDict
from typing import List, Union
from .function_registry import get_modeled_function_index, modeled_functions
from tqdm import tqdm
from .bingoggles_output import *


class InterprocHelper:
    def __init__(
        self,
        binary_view: BinaryView,
        original_tainted_params: tuple,
        origin_function: Function,
        tainted_param_map: set,
        analysis: "Analysis",
    ) -> None:
        """
        Helper class for interprocedural taint analysis and variable tracking.

        This class provides methods to handle MLIL instructions, gather call data,
        and propagate taint information across function boundaries during analysis.

        Args:
            binary_view (BinaryView): The Binary Ninja BinaryView object.
            original_tainted_params (tuple): The original tainted parameter(s).
            origin_function (Function): The function where taint originated.
            tainted_param_map (set): Set of tainted parameter mappings.
            analysis (Analysis): The main analysis object coordinating taint analysis.
        """
        self.bv = binary_view
        self.recursion_limit = 20
        self.sub_functions_analyzed = 0
        self.origin_function = origin_function
        self.original_tainted_params = original_tainted_params
        self.tainted_param_map = tainted_param_map
        self.analysis: "Analysis" = analysis

    def does_variable_taint_param(
        original_tainted_params: tuple,
        variable: Union[Variable, SSAVariable],
        var_mapping: dict,
    ) -> bool: ...

    #:TODO

    def handle_mlil_store_ssa(self, loc, tainted_variables: set) -> None:
        """
        Handle MLIL_STORE_SSA instructions by marking the destination variable as tainted.

        Args:
            loc: The MLIL instruction location.
            tainted_variables (set): Set of currently tainted variables.

        Returns:
            None
        """
        tv = create_tainted_var_offset_from_load_store(
            loc, tainted_variables, self.analysis
        )
        if tv is not None:
            tainted_variables.add(tv)

    def gather_mlil_call_data(
        self, loc, tainted_variables: set
    ) -> Union[None, CallData]:
        """
        Gather information about an MLIL call instruction, including tainted parameters.

        Args:
            loc: The MLIL call instruction.
            tainted_variables (set): Set of currently tainted variables.

        Returns:
            CallData: An object containing call parameters, the called function, and taint mapping.
        """
        # Extract the parameters involved in the call
        call_params = [
            param for param in loc.params if isinstance(param, MediumLevelILVarSsa)
        ]

        call_object = addr_to_func(
            self.bv,
            loc.dest.value.value,
        )

        if call_object:
            function_call_params = call_object.parameter_vars
            zipped_params = list(zip(call_params, function_call_params))

            # Identify sub-function parameters that are tainted by comparing the underlying variable
            tainted_sub_params = [
                param[1].name
                for param in zipped_params
                if any(
                    tv.variable == param[0].ssa_form.var
                    for tv in tainted_variables
                    if tv is not None
                )
            ]

            return CallData(
                call_params,
                call_object,
                function_call_params,
                zipped_params,
                tainted_sub_params,
            )

        return None

    def gather_interproc_data(
        self, mlil_loc, function_node, analysis: "Analysis", call_data: CallData
    ) -> Union[list, None]:
        """
        Gather interprocedural taint data for a function call.

        Args:
            mlil_loc: The MLIL instruction location.
            function_node: The current function node.
            analysis: The Analysis object performing the taint analysis.
            call_data (CallData): Data about the call site.

        Returns:
            Union[list, None]: The results of the interprocedural taint analysis.
        """
        interproc_results_list = []
        imported_function = analysis.resolve_function_type(mlil_loc)
        interproc_results = None
        normalized_function_name = get_modeled_function_name_at_callsite(
            function_node, mlil_loc
        )

        if self.recursion_limit < self.sub_functions_analyzed:
            for param in self.original_tainted_params:
                _, tainted_func_param = get_func_param_from_call_param(
                    analysis.bv, mlil_loc, param
                )

                if normalized_function_name:
                    interproc_results = analysis.analyze_function_taint(
                        normalized_function_name, tainted_func_param, mlil_loc
                    )

                elif imported_function:
                    #:TODO work on this
                    interproc_results = analysis.trace_function_taint(
                        function_node=call_data.call_object,
                        tainted_params=tuple(call_data.tainted_sub_params),
                        binary_view=self.bv,
                    )

                elif not normalized_function_name and not imported_function:
                    resolved_function_object = resolve_got_callsite(
                        function_node.view, mlil_loc.dest.value.value
                    )

                    if resolved_function_object:
                        interproc_results = analysis.analyze_function_taint(
                            resolved_function_object.name, param, mlil_loc
                        )

                    else:
                        interproc_results = analysis.trace_function_taint(
                            function_node=call_data.call_object,
                            tainted_params=tuple(call_data.tainted_sub_params),
                            binary_view=self.bv,
                        )

            self.sub_functions_analyzed += 1
            interproc_results_list.append(interproc_results)

        return interproc_results_list

    def handle_mlil_call_ssa(
        self,
        function_node: Function,
        analysis,
        tainted_variables: set,
        verbose: bool,
        loc,
    ) -> None:
        """
        Handle MLIL_CALL_SSA instructions, propagating taint through function calls.

        Args:
            function_node (Function): The current function node.
            analysis: The Analysis object.
            tainted_variables (set): Set of currently tainted variables.
            verbose (bool): Whether to print verbose output.
            loc: The MLIL instruction location.

        Returns:
            None
        """
        call_data = self.gather_mlil_call_data(loc, tainted_variables)
        if call_data is None:
            return

        if not call_data.call_object:
            return

        if verbose:
            print(
                f"[{Fore.GREEN}INFO{Fore.RESET}] Analyzing sub-function call: {call_data.call_object} for tainted parameters"
            )

        list_ipc_data = self.gather_interproc_data(
            loc, function_node, analysis, call_data
        )

        for ipc_data in list_ipc_data:
            if ipc_data and isinstance(ipc_data, InterprocTaintResult):
                # Map back the tainted sub-function parameters to the current function's variables
                tainted_sub_variables = [
                    param[0].ssa_form.var
                    for param in call_data.zipped_params
                    if param[1].name in ipc_data.tainted_param_names
                ]

                for sub_var in tainted_sub_variables:
                    append_bingoggles_var_by_type(
                        sub_var, tainted_variables, loc, analysis
                    )

                if ipc_data.is_return_tainted:
                    if loc.vars_written:
                        var = loc.vars_written[0]
                        append_bingoggles_var_by_type(
                            var, tainted_variables, loc, analysis
                        )

            elif ipc_data and isinstance(ipc_data, FunctionModel):
                tainted_sub_variables = [
                    call_data.zipped_params[i][0].ssa_form.var
                    for i in ipc_data.taint_destinations
                    if i < len(call_data.zipped_params)
                ]

                for sub_var in tainted_sub_variables:
                    append_bingoggles_var_by_type(
                        sub_var, tainted_variables, loc, analysis
                    )

                if ipc_data.taints_return:
                    if loc.vars_written:
                        var = loc.vars_written[0]
                        append_bingoggles_var_by_type(
                            var, tainted_variables, loc, analysis
                        )

    def mlil_handler(
        self, analysis, loc, tainted_variables: set, function_node: Function, verbose
    ) -> None:
        """
        Dispatch handler for MLIL instructions, calling the appropriate handler based on operation type.

        Args:
            analysis: The Analysis object.
            loc: The MLIL instruction location.
            tainted_variables (set): Set of currently tainted variables.
            function_node (Function): The current function node.
            verbose (bool): Whether to print verbose output.

        Returns:
            None
        """
        match loc.operation.value:
            case MediumLevelILOperation.MLIL_STORE_SSA.value:
                self.handle_mlil_store_ssa(loc, tainted_variables)

            case MediumLevelILOperation.MLIL_LOAD_SSA.value:
                #:TODO add support for load SSA
                ...

            case MediumLevelILOperation.MLIL_STORE_STRUCT_SSA.value:
                #:TODO add support for struct store
                ...

            case MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA.value:
                #:TODO add support for struct load
                ...

            case MediumLevelILOperation.MLIL_SET_VAR_SSA.value:
                var = loc.vars_written[0]
                append_bingoggles_var_by_type(var, tainted_variables, loc, analysis)

            case MediumLevelILOperation.MLIL_CALL_SSA.value:
                self.handle_mlil_call_ssa(
                    function_node, analysis, tainted_variables, verbose, loc
                )

            case MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD.value:
                tainted_variables.add(
                    TaintedVar(loc.dest, TaintConfidence.Tainted, loc.address)
                )

            case _:
                if loc.operation in [
                    MediumLevelILOperation.MLIL_RET.value,
                    MediumLevelILOperation.MLIL_GOTO.value,
                    MediumLevelILOperation.MLIL_IF.value,
                    MediumLevelILOperation.MLIL_NORET.value,
                    MediumLevelILOperation.MLIL_SYSCALL_SSA.value,
                ]:
                    return

                else:
                    if loc.vars_written:
                        var = loc.vars_written[0]
                        if analysis.verbose:
                            op_name = MediumLevelILOperation(loc.operation).name
                            reads = ", ".join(
                                getattr(v, "name", str(getattr(v, "var", v)))
                                for v in (loc.vars_read or [])
                            ) or "None"
                            print(
                                f"[{Fore.YELLOW}WARN{Fore.RESET}] Unhandled MLIL op "
                                f"{Fore.CYAN}{op_name}{Fore.RESET} at {loc.address:#x}; "
                                f"tainting written var {Fore.MAGENTA}{getattr(var, 'name', str(var))}{Fore.RESET} "
                                f"from reads [{reads}]"
                            )
                        append_bingoggles_var_by_type(
                            var, tainted_variables, loc, analysis
                        )
    def trace_through_node(
        self,
        analysis,
        function_node: Function,
        tainted_variables: set,
        variable_mapping: dict,
        verbose: bool = False,
    ) -> None:
        """
        Trace taint propagation through all MLIL instructions in a function node.

        Args:
            analysis: The Analysis object.
            function_node (Function): The function node to analyze.
            tainted_variables (set): Set of currently tainted variables.
            variable_mapping (dict): Mapping of variable assignments.
            verbose (bool): Whether to print verbose output.

        Returns:
            None
        """
        all_mlil_locs = (
            mlil_loc for block in function_node.medium_level_il for mlil_loc in block
        )
        for mlil_loc in all_mlil_locs:
            loc = mlil_loc.ssa_form
            self.mlil_handler(analysis, loc, tainted_variables, function_node, verbose)

            # Map variables written to the variables read in the current instruction
            for var_assignment in loc.vars_written:
                variable_mapping[var_assignment] = loc.vars_read

            # If any read variable is tainted, mark the written variables as tainted
            tainted_variables.update([t for t in tainted_variables if t])
            if None in tainted_variables:
                tainted_variables.discard(None)

            # Check if any read variable matches any tainted variable
            if any(
                variables_match(tv.variable, read_var)
                for tv in tainted_variables
                for read_var in loc.vars_read
                if tv is not None
            ):
                for var in loc.vars_written:
                    append_bingoggles_var_by_type(
                        var, tainted_variables, loc, self.analysis
                    )

    def print_banner_interproc_banner(
        self,
        verbose: bool,
        trace_function_taint_printed: bool,
        tainted_params: List,
        function_node: Function,
    ) -> None:
        """
        Print a banner for the start of a taint trace if verbose mode is enabled.

        Args:
            verbose (bool): Whether to print verbose output.
            trace_function_taint_printed (bool): Whether the banner has already been printed.
            tainted_params (list): The tainted parameter(s) being traced.
            function_node (Function): The function node being analyzed.

        Returns:
            None
        """
        if verbose and not trace_function_taint_printed:
            print(
                f"tainted_param: Variable | str {Fore.RESET})\n-> {Fore.LIGHTBLUE_EX}{function_node}"
                f"{Fore.RESET}:{Fore.BLUE}{tainted_params}{Fore.RESET}\n{Fore.GREEN}{'='*113}{Fore.RESET}"
            )
            trace_function_taint_printed = True

    def walk_variable(self, var_mapping: dict, key_names: set) -> set:
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
                new_variables.update(var_mapping[var_name])

            else:
                new_variables.add(var_name)

        return self.walk_variable(var_mapping, new_variables)

    def convert_str_params_to_var(
        self,
        tainted_params: list,
        function_node: Function,
        tainted_variables: set,
    ) -> None:
        """
        Converts string parameter names, Variables, or SSAVariables to SSA Variable objects and adds them to the tainted set.

        This method processes each entry in `tainted_params`, resolving string names to SSA Variable objects
        within the given function. The resolved variables are then wrapped and added to the `tainted_variables` set
        for taint analysis.

        Args:
            tainted_params (Union[List, Variable, SSAVariable, str]):
                The parameters to convert, which may be a list or a single Variable, SSAVariable, or string name.
            function_node (Function): The Binary Ninja function object containing the parameters.
            tainted_variables (set): The set to which resolved tainted variables will be added.

        Returns:
            None
        """
        for param in tainted_params:
            if isinstance(param, str):
                var_obj = str_param_to_var_object(function_node, param, ssa_form=True)
                if var_obj:
                    first_var_use = self.analysis.find_first_var_use(
                        function_node, var_obj
                    )

                    if first_var_use:
                        mlil_loc = function_node.get_llil_at(first_var_use).mlil
                        append_bingoggles_var_by_type(
                            var_obj,
                            tainted_variables,
                            mlil_loc,
                            self.analysis,
                        )

            elif isinstance(param, (Variable, SSAVariable)):
                first_var_use = self.analysis.find_first_var_use(function_node, param)

                if first_var_use:
                    mlil_loc = function_node.get_llil_at(first_var_use).mlil

                    append_bingoggles_var_by_type(
                        param,
                        tainted_variables,
                        mlil_loc,
                        self.analysis,
                    )


class VargFunctionCallResolver:
    """
    A class to resolve and patch variadic function calls in a Binary Ninja BinaryView.

    Args:
        binary_view (BinaryView): The Binary Ninja BinaryView object representing the binary.
        verbose (bool): If True, enables verbose output during resolution and patching.
    """

    def __init__(self, binary_view: BinaryView, verbose: bool = True):
        self.bv = binary_view
        self.verbose = verbose

    def save_patches_made_to_bndb(self, output_bndb_path: str = None) -> None:
        """
        Save the current state of the BinaryView to a .bndb database file.

        If no output path is provided, the function will use the original filename with a .bndb extension.
        This function is typically used after making modifications or patches to the binary, ensuring that
        all changes are persisted in a Binary Ninja database file.

        Args:
            bv (BinaryView): The Binary Ninja BinaryView object representing the binary.
            output_bndb_path (str, optional): The path where the .bndb file should be saved. If None,
                the function will derive the path from the original filename.
        """

        if output_bndb_path is None:
            if self.bv.file.original_filename[-5:] == ".bndb":
                output_bndb_path = self.bv.file.original_filename
            else:
                output_bndb_path = (
                    self.bv.file.original_filename + ".bndb"
                    if not self.bv.file.original_filename.endswith(".bndb")
                    else self.bv.file.original_filename
                )

        success = self.bv.file.create_database(output_bndb_path, None, None)
        if success:
            print(f"Successfully saved BinaryView to {output_bndb_path}")
        else:
            print(f"Failed to save BinaryView to {output_bndb_path}")

    def resolve_and_patch(
        self,
        resolved: List[FunctionModel],
        function_node: Function,
        mlil_loc: MediumLevelILInstruction,
    ) -> Union[FunctionModel, None]:
        """
        Resolve and patch a modeled variadic function call if it matches a known model.

        Args:
            resolved (List[FunctionModel]): A list of already resolved function models to avoid duplicates.
            function_node (Function): The Binary Ninja function object containing the call.
            mlil_loc (MediumLevelILInstruction): The MLIL instruction representing the function call.

        Returns:
            FunctionModel or None: The resolved function model if a new one was found and patched, otherwise None.
        """
        section = self.bv.get_sections_at(function_node.start)
        if section:
            name = section[0].name
            if name == ".synthetic_builtins":
                return None

        model = resolve_modeled_variadic_function(function_node, mlil_loc)
        if model and model not in resolved:
            patch_function_params(function_node, mlil_loc, model)
            resolved.append(model)
            return model

        return None

    def is_in_text_section(self, function_node: Function) -> bool:
        """
        Check if the given function is located within the .text section of the binary.

        Args:
            function_node (Function): The Binary Ninja function object to check.

        Returns:
            bool: True if the function is in the .text section, False otherwise.
        """
        text_section = self.bv.sections.get(".text")
        if not text_section:
            return False

        function_start_address = function_node.start
        text_section_start = text_section.start
        text_section_end = text_section.end

        return text_section_start <= function_start_address < text_section_end

    def resolve_varg_func_calls(
        self, functions_to_resolve: list = [], output_path: str = None
    ) -> None:
        """
        Resolves variadic function calls within specified functions or all functions in the binary view.

        Args:
            functions_to_resolve (list, optional): A list of function objects to process.
                                                   If empty, all functions in the binary view
                                                   (`self.bv.functions`) will be processed.
                                                   Defaults to an empty list.

        A loading bar is displayed to show the progress of the resolution process.
        """
        resolved = []
        functions_to_iterate = 0
        if not functions_to_resolve:
            functions_to_iterate = self.bv.functions
        else:
            functions_to_iterate = functions_to_resolve

        if self.verbose:
            iterator = tqdm(functions_to_iterate, desc="Resolving variadic calls")
        else:
            iterator = functions_to_iterate

        for function_node in iterator:
            if self.is_in_text_section(function_node):
                for block in function_node.medium_level_il:
                    for mlil_loc in block:
                        if isinstance(mlil_loc, MediumLevelILCall):
                            self.resolve_and_patch(resolved, function_node, mlil_loc)

        if output_path:
            self.save_patches_made_to_bndb(output_path)
        else:
            self.save_patches_made_to_bndb()


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

        It supports full-function taint tracing, cross-function taint mapping (calls and returns), and modeling of
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
            - init_function_var_trace(...): Initialize taint tracing for a function variable.
            - init_global_var_trace(...): Initialize taint tracing for a global variable.
            - init_struct_member_trace(...): Initialize taint tracing for a struct member variable.
            - render_sliced_output(...): Render the output of a taint slice for visualization or further analysis,
              with options for colored output and log file generation.
        """
        self.bv = binaryview
        self.verbose = verbose
        self.libraries_mapped = libraries_mapped
        self.glob_refs_memoized = {}
        self.trace_function_taint_printed = False

    @cache
    def get_sliced_calls(
        self,
        data: List[TaintedLOC],
        func_name: str,
        propagated_vars: List[
            Union[TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar]
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
            propagated_vars (List[Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]]):
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

            if loc.operation.value == MediumLevelILOperation.MLIL_CALL.value:
                param_map = param_var_map(loc.params, propagated_vars)
                call_function_object = addr_to_func(self.bv, loc.dest.value.value)
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

    def init_function_var_trace(
        self,
        slice_type: SliceType,
        target: TaintTarget,
        instr_mlil: MediumLevelILInstruction,
        func_obj: Function,
    ):
        """
        Initialize taint tracing for a function variable.

        This function identifies and traces the propagation of a variable within a function
        using either forward or backward slicing. It resolves the variable reference using the
        function's context and analyzes its usage in MLIL instructions.

        Args:
            slice_type (SliceType): Direction of the slice (Forward or Backward).
            target (TaintTarget): The target function variable to trace, including its name and location.
            instr_mlil (MediumLevelILInstruction): The MLIL instruction at the target location.
            func_obj (Function): The Binary Ninja function object containing the variable.

        Returns:
            tuple[List[TaintedLOC], List[TaintedVar]]:
                - A list of tainted code locations (TaintedLOC) where taint propagation was detected.
                - A list of all propagated variables (TaintedVar) found during the trace.
        """
        var_object = str_to_var_object(target.variable, func_obj)

        if var_object:
            if slice_type == SliceType.Forward:
                return trace_tainted_variable(
                    self, func_obj, instr_mlil, var_object, SliceType.Forward
                )

            elif slice_type == SliceType.Backward:
                return trace_tainted_variable(
                    self, func_obj, instr_mlil, var_object, SliceType.Backward
                )

            else:
                raise TypeError(
                    f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                )

    def init_global_var_trace(
        self,
        slice_type: SliceType,
        target: TaintTarget,
        instr_mlil: MediumLevelILInstruction,
        func_obj: Function,
    ):
        """
        Initialize taint tracing for a global variable.

        This function identifies and traces the propagation of a global variable through a function
        using either forward or backward slicing. It resolves the global variable reference from
        Binary Ninja's symbol table and analyzes its usage in MLIL instructions.

        Args:
            slice_type (SliceType): Direction of the slice (Forward or Backward).
            target (TaintTarget): The target global variable to trace, including its name and location.
            instr_mlil (MediumLevelILInstruction): The MLIL instruction at the target location.
            func_obj (Function): The Binary Ninja function object containing the global variable.

        Returns:
            tuple[List[TaintedLOC], List[TaintedVar]]:
                - A list of tainted code locations (TaintedLOC) where taint propagation was detected.
                - A list of all propagated variables (TaintedVar) found during the trace.
        """
        symbol = [
            s
            for s in self.bv.get_symbols()
            if s.type.value == SymbolType.DataSymbol.value and s.name == target.variable
        ]
        if symbol:
            const_ptr = None
            symbol_obj = None

            for op in flat(instr_mlil.operands):
                if hasattr(op, "address"):
                    s = get_symbol_from_const_ptr(self.bv, op)
                    if s and s in [i for i in symbol]:
                        const_ptr = op
                        symbol_obj = s
                        break

            tainted_global = TaintedGlobal(
                target.variable,
                TaintConfidence.Tainted,
                target.loc_address,
                const_ptr,
                symbol_obj,
            )

            if slice_type == SliceType.Forward:
                return trace_tainted_variable(
                    self, func_obj, instr_mlil, tainted_global, SliceType.Forward
                )

            elif slice_type == SliceType.Backward:
                return trace_tainted_variable(
                    self, func_obj, instr_mlil, tainted_global, SliceType.Backward
                )

            else:
                raise TypeError(
                    f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                )

    def init_struct_member_trace(
        self,
        slice_type: SliceType,
        target: TaintTarget,
        instr_mlil: MediumLevelILInstruction,
        func_obj: Function,
    ):
        """
        Initialize taint tracing for a struct member variable.

        This function identifies and traces the propagation of a struct member variable
        through a function using either forward or backward slicing. It analyzes the MLIL
        and HLIL instructions to determine the variable's usage and taint propagation.

        Args:
            slice_type (SliceType): Direction of the slice (Forward or Backward).
            target (TaintTarget): The target struct member variable to trace, including its name and location.
            instr_mlil (MediumLevelILInstruction): The MLIL instruction at the target location.
            func_obj (Function): The Binary Ninja function object containing the struct member.

        Returns:
            tuple[List[TaintedLOC], List[TaintedVar]]:
                - A list of tainted code locations (TaintedLOC) where taint propagation was detected.
                - A list of all propagated variables (TaintedVar) found during the trace.
        """
        instr_hlil = func_obj.get_llil_at(target.loc_address).hlil

        try:
            struct_offset = instr_mlil.ssa_form.src.offset
        except AttributeError:
            struct_offset = instr_mlil.ssa_form.offset

        if instr_hlil.operation == HighLevelILOperation.HLIL_ASSIGN.value:
            destination = instr_hlil.dest

            if destination.operation == HighLevelILOperation.HLIL_DEREF_FIELD.value:
                struct_offset = destination.offset
                base_expr = destination.src

                if base_expr.operation == HighLevelILOperation.HLIL_VAR.value:
                    base_var = base_expr.var
                    tainted_struct_member = TaintedStructMember(
                        target.loc_address,
                        target.variable,
                        struct_offset,
                        base_var,
                        instr_mlil.dest.var,
                        TaintConfidence.Tainted,
                    )

                    if slice_type == SliceType.Forward:
                        return trace_tainted_variable(
                            self,
                            func_obj,
                            instr_mlil,
                            tainted_struct_member,
                            SliceType.Forward,
                        )

                    elif slice_type == SliceType.Backward:
                        return trace_tainted_variable(
                            self,
                            func_obj,
                            instr_mlil,
                            tainted_struct_member,
                            SliceType.Backward,
                        )

                    else:
                        raise TypeError(
                            f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                        )

        elif instr_mlil.operation.value == MediumLevelILOperation.MLIL_SET_VAR.value:
            source = instr_mlil.src
            base_var = instr_mlil.src.src
            if source.operation.value == MediumLevelILOperation.MLIL_LOAD_STRUCT.value:
                tainted_struct_member = TaintedStructMember(
                    target.loc_address,
                    target.variable,
                    struct_offset,
                    base_var,
                    instr_mlil.src.src.var,
                    TaintConfidence.Tainted,
                )

                if slice_type == SliceType.Forward:
                    return trace_tainted_variable(
                        self,
                        func_obj,
                        instr_mlil,
                        tainted_struct_member,
                        SliceType.Forward,
                    )

                elif slice_type == SliceType.Backward:
                    return trace_tainted_variable(
                        self,
                        func_obj,
                        instr_mlil,
                        tainted_struct_member,
                        SliceType.Backward,
                    )

                else:
                    raise TypeError(
                        f"[{Fore.RED}ERROR{Fore.RESET}] slice_type must be either forward or backward"
                    )

            elif source.operation.value == MediumLevelILOperation.MLIL_VAR_FIELD:
                tainted_struct_member = TaintedStructMember(
                    target.loc_address,
                    target.variable,
                    struct_offset,
                    base_var,
                    instr_mlil.dest,
                    TaintConfidence.Tainted,
                )

                if slice_type == SliceType.Forward:
                    return trace_tainted_variable(
                        self,
                        func_obj,
                        instr_mlil,
                        tainted_struct_member,
                        SliceType.Forward,
                    )

                elif slice_type == SliceType.Backward:
                    return trace_tainted_variable(
                        self,
                        func_obj,
                        instr_mlil,
                        tainted_struct_member,
                        SliceType.Backward,
                    )

        else:
            raise ValueError(
                f"[{Fore.RED}ERORR{Fore.RESET}]Couldn't find variable reference, insure that you're using the MLIL to identify your target variable"
            )

    def init_function_param_trace(self, target: TaintTarget, func_obj: Function):
        """
        Initialize taint tracing for a function parameter.

        This function resolves the specified parameter from a `TaintTarget`, identifies the
        first MLIL reference to that parameter, and begins a forward taint trace from that point
        using `trace_tainted_variable`.

        Args:
            target (TaintTarget): A taint target specifying the location and parameter name or object to trace.
            func_obj (Function): The Binary Ninja function object containing the parameter.

        Returns:
            tuple[List[TaintedLOC], List[TaintedVar]]:
                - A list of tainted code locations (TaintedLOC) where taint propagation was detected.
                - A list of all propagated variables (TaintedVar) found during the trace.

        Raises:
            AttributeError: If the parameter cannot be resolved or no references to it are found.
            ValueError: If the resolved reference is not traceable through MLIL.
        """
        if isinstance(target.variable, str):
            target_param = find_param_by_name(func_obj, target.variable)

        elif isinstance(target.variable, MediumLevelILVar):
            target_param = target.variable.var

        else:
            target_param = find_param_by_name(func_obj, target.variable.name)

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
        return trace_tainted_variable(
            self, func_obj, first_ref_mlil, target_param, SliceType.Forward
        )

    @cache
    def tainted_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        output: OutputMode = OutputMode.Returned,
        slice_type: SliceType = SliceType.Forward,
        log_file: Optional[str] = None,
    ) -> Union[tuple[list, str, List[Variable]], None]:
        """
        Run a forward or backward taint analysis slice from a given variable.

        Traces the propagation of a target variable (local, global, struct member, or function parameter)
        within a single function, using either forward or backward slicing. Returns the list of tainted
        instructions, the function name, and the propagated variables.

        Args:
            target (TaintTarget): The variable or memory location to start slicing from.
            var_type (SlicingID): The type of the target (FunctionVar, GlobalVar, StructMember, FunctionParam).
            output (OutputMode, optional): Whether to print or return the slice results. Default is Returned.
            slice_type (SliceType, optional): Slicing direction (Forward or Backward). Default is Forward.
            log_file (str, optional): Path to save output to a log file. Default is None (no logging).

        Returns:
            tuple[list, str, list]:
                - List of TaintedLOC objects (instructions visited during the slice)
                - Name of the function containing the slice
                - List of propagated variables
            Returns None if the analysis fails (e.g., unresolved instruction or function context).
        """

        if hasattr(target.loc_address, "start"):
            func_obj = target.loc_address

        else:
            func_obj = addr_to_func(self.bv, target.loc_address)
            if func_obj is None:
                raise ValueError(
                    f"Could not find a function containing address: {target.loc_address:#0x}"
                )

        sliced_func = []
        propagated_vars = []

        instr_mlil = None
        if var_type != SlicingID.FunctionParam:
            instr_mlil = func_obj.get_llil_at(target.loc_address).mlil
            if instr_mlil is None:
                raise AttributeError(
                    f"[{Fore.RED}Error{Fore.RESET}] The address you provided for the target variable is likely wrong."
                )

        match var_type:
            case SlicingID.FunctionVar:
                sliced_func, propagated_vars = self.init_function_var_trace(
                    slice_type, target, instr_mlil, func_obj
                )

            case SlicingID.GlobalVar:
                sliced_func, propagated_vars = self.init_global_var_trace(
                    slice_type, target, instr_mlil, func_obj
                )

            case SlicingID.StructMember:
                sliced_func, propagated_vars = self.init_struct_member_trace(
                    slice_type, target, instr_mlil, func_obj
                )

            case SlicingID.FunctionParam:
                sliced_func, propagated_vars = self.init_function_param_trace(
                    target, func_obj
                )

            case _:
                raise TypeError(
                    f"{Fore.RED}var_type must be either SlicingID.FunctionParam or SlicingID.FunctionVar, please see the SlicingID class{Fore.RESET}"
                )

        if output == OutputMode.Printed:
            render_sliced_output(
                sliced_func,
                OutputMode.Printed,
                func_obj,
                propagated_vars,
                self.verbose,
                True if log_file is None else False,
                log_file,
            )

        elif output == OutputMode.Returned:
            tainted_locs, func_name, tainted_vars = render_sliced_output(
                sliced_func,
                OutputMode.Returned,
                func_obj,
                propagated_vars,
                self.verbose,
                True if log_file is None else False,
                log_file,
            )
            return tainted_locs, func_name, tainted_vars

        else:
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
        log_file: Optional[str] = None,
    ) -> OrderedDict:
        """
        Run a complete interprocedural taint slice, recursively tracking taint across function calls.

        Traces taint propagation from a starting variable or parameter, following its flow through MLIL instructions
        and across function boundaries. Produces a call graph-like structure showing all taint paths, optionally
        including imported functions and resolving variadic calls if requested.

        Args:
            target (TaintTarget): The starting address and variable for the slice.
            var_type (SlicingID): The type of the target (FunctionVar or FunctionParam).
            slice_type (SliceType, optional): Slicing direction (Forward or Backward). Default is Forward.
            output (OutputMode, optional): Whether to print or return results. Default is Returned.
            analyze_imported_functions (bool, optional): Recurse into imported functions if True. Default is False.
            log_file (str, optional): Path to save output to a log file. Default is None (no logging).

        Returns:
            OrderedDict:
                Maps (function_name, variable) to (tainted_locations, propagated_vars), e.g.:
                    {
                        ("function", rdi): ([TaintedLOC, ...], [TaintedVar, ...]),
                        ...
                    }
            If the analysis fails, returns an empty OrderedDict.
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
            sliced_calls = self.get_sliced_calls(
                tuple(slice_data), func_name, tuple(propagated_vars)
            )
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

        # Perform initial slice
        # try:
        slice_data, og_func_name, propagated_vars = self.tainted_slice(
            target=target,
            var_type=var_type,
            slice_type=slice_type,
        )
        # except TypeError:
        #     raise TypeError(
        #         f"[{Fore.RED}ERROR{Fore.RESET}] Address is likely wrong in target | got: {target.loc_address:#0x} for {target.variable}"
        #     )

        # Add first slice to the result cache
        parent_func_obj = func_name_to_object(self.bv, og_func_name)
        key = (og_func_name, str_to_var_object(target.variable, parent_func_obj))
        propagation_cache[key] = (slice_data, propagated_vars)

        # Check for initial cross-function taint propagation
        sliced_calls = self.get_sliced_calls(
            tuple(slice_data), og_func_name, tuple(propagated_vars)
        )
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
                        v.variable.name if hasattr(v.variable, "name") else v.variable
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

        if output == OutputMode.Printed:
            for (fn_name, var), (locs, prop_vars) in propagation_cache.items():
                print(
                    f"\n{Fore.CYAN}Function:{Fore.RESET} {Fore.GREEN}{fn_name}{Fore.RESET}"
                )
                print(
                    f"{Fore.CYAN}Variable:{Fore.RESET} {Fore.YELLOW}{var.name if hasattr(var, 'name') else var}{Fore.RESET}"
                )
                print(f"{Fore.CYAN}{'='*50}{Fore.RESET}")

                if locs:
                    use_color = True
                    if log_file:
                        set_output_options(use_color=use_color, log_file=log_file)
                    pretty_print_path_data(locs)
                else:
                    print(f"{Fore.RED}No tainted locations found{Fore.RESET}")

                # print()  # Add spacing between function outputs

        return propagation_cache

    def find_first_var_use(
        self, func: Function, var_or_name: Union[SSAVariable, Variable, str]
    ) -> Union[int, None]:
        """
        Return the first MLIL instruction where the given variable is used.

        Args:
            func (Function): The Binary Ninja Function object.
            var_or_name (Variable | str): The variable to search for.

        Returns:
            MediumLevelILInstruction | None: The first MLIL instruction using the variable, or None if not found.
        """
        target_var = var_or_name
        matches = [
            v
            for v in func.mlil.ssa_form.vars
            if (hasattr(var_or_name, "name") and v.name == var_or_name.name)
            or (not hasattr(var_or_name, "name") and v.name == var_or_name)
        ]
        if not matches:
            return None

        target_var = matches[0]

        for block in func.mlil.ssa_form:
            for instr in block:
                if target_var in instr.vars_read or target_var in instr.vars_written:
                    return instr.address

        return None

    def trace_function_taint_init(
        self,
        function_node: Union[int, Function],
        tainted_params: Union[tuple, str, Variable, SSAVariable],
        binary_view: Union[BinaryView, None] = None,
        origin_function: Union[Function, None] = None,
        original_tainted_params: tuple = None,
        tainted_param_map: Union[dict, None] = None,
    ) -> tuple:
        if isinstance(function_node, int):
            function_node = addr_to_func(self.bv, function_node)

        if origin_function is None:
            origin_function = function_node

        if tainted_param_map is None:
            tainted_param_map = {}

        temp = []
        if isinstance(tainted_params, tuple) and len(tainted_params) > 1:
            for param in tainted_params:
                temp.append(get_ssa_variable(function_node, param))

            tainted_params = temp

        else:
            tainted_params = [get_ssa_variable(function_node, tainted_params)]

        if original_tainted_params is None:
            original_tainted_params = tainted_params

        if binary_view is None:
            binary_view = self.bv

        return (
            function_node,
            tainted_params,
            binary_view,
            origin_function,
            original_tainted_params,
            tainted_param_map,
        )

    @cache
    def trace_function_taint(
        self,
        function_node: Union[int, Function],
        tainted_params: Union[tuple, Variable, str],
        binary_view: BinaryView,
        origin_function: Function = None,
        original_tainted_params: Union[Variable, str, tuple] = None,
        tainted_param_map: dict = None,
    ) -> InterprocTaintResult:
        """
        Perform interprocedural taint analysis on a function to determine if taint propagates to its return value or parameters.
        """
        (
            function_node,
            tainted_params,
            binary_view,
            origin_function,
            original_tainted_params,
            tainted_param_map,
        ) = self.trace_function_taint_init(
            function_node,
            tainted_params,
            binary_view,
            origin_function,
            original_tainted_params,
            tainted_param_map,
        )

        print(f"\n{Fore.CYAN}[DEBUG]{Fore.RESET} Taint analysis initialized:")
        print(
            f"  {Fore.YELLOW}Function:{Fore.RESET} {function_node.name} @ {function_node.start:#x}"
        )
        print(
            f"  {Fore.YELLOW}Params to trace:{Fore.RESET} {[getattr(p, 'name', str(p)) for p in tainted_params]}"
        )
        print(
            f"  {Fore.YELLOW}Origin function:{Fore.RESET} {origin_function.name if origin_function else 'None'}"
        )
        print(
            f"  {Fore.YELLOW}Original tainted params:{Fore.RESET} {original_tainted_params}"
        )
        print(f"{Fore.GREEN}{'='*80}{Fore.RESET}")

        i_h = InterprocHelper(
            binary_view,
            original_tainted_params,
            origin_function,
            tainted_param_map,
            self,
        )

        tainted_variables = set()
        variable_mapping = {}
        tainted_parameters = set()

        # Convert string parameter names to Variable objects in SSA form and wrap them in TaintedVar
        i_h.convert_str_params_to_var(tainted_params, function_node, tainted_variables)

        i_h.print_banner_interproc_banner(
            self.verbose,
            self.trace_function_taint_printed,
            tainted_params,
            function_node,
        )

        i_h.trace_through_node(
            self, function_node, tainted_variables, variable_mapping, self.verbose
        )

        # DEBUG remove later
        from pprint import pprint

        pprint(variable_mapping)

        # Extract underlying variables from TaintedVar before walking the mapping.
        underlying_tainted = {tv.variable for tv in tainted_variables if tv is not None}

        # DEBUG remove later
        print("Underlying tainted variables:", underlying_tainted)
        print("Function parameter vars:", [p for p in origin_function.parameter_vars])

        var_mapping_vars = {
            (key.var if hasattr(key, "var") else key): value
            for key, value in variable_mapping.items()
        }

        # DEBUG remove later
        pprint(var_mapping_vars)
        pprint(tainted_variables)

        # Determine all parameters that are tainted by walking through the variable mapping.
        func_params = origin_function.parameter_vars
        for var in i_h.walk_variable(variable_mapping, underlying_tainted):
            if var in var_mapping_vars and not any(
                v in func_params for v in var_mapping_vars[var]
            ):
                mapped_vars = var_mapping_vars[var]
                for mapped_var in mapped_vars:
                    matching_param = next(
                        (
                            param
                            for param in origin_function.parameter_vars
                            if hasattr(mapped_var, "name")
                            and hasattr(param, "name")
                            and mapped_var.name == param.name
                        ),
                        None,
                    )

                    if matching_param is not None:
                        tainted_parameters.add(matching_param)

        # Build tainted parameter map: if multiple parameters became tainted during analysis,
        # map the original input parameter to all other parameters it influenced
        if len(tainted_parameters) > 1:
            original_param = (
                original_tainted_params[0]
                if isinstance(original_tainted_params, (list, tuple))
                else original_tainted_params
            )

            original_key = None
            for param in origin_function.parameter_vars:
                if (
                    hasattr(original_param, "name")
                    and hasattr(param, "name")
                    and original_param.name == param.name
                ):
                    original_key = param
                    break

            if original_key:
                other_tainted = [p for p in tainted_parameters if p != original_key]
                if other_tainted:
                    tainted_param_map[original_key] = other_tainted

        # Find out if return variable is tainted
        ret_variable_tainted = False

        for t_var in tainted_variables:
            loc = origin_function.get_llil_at(t_var.loc_address)
            if loc:
                var_use_sites = get_use_sites(loc.mlil.ssa_form, t_var.variable, self)
                if var_use_sites:
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
            MediumLevelILOperation.MLIL_CONST_PTR.value,
            MediumLevelILOperation.MLIL_CONST.value,
        ]:
            target_addr = call_target.constant
        else:
            return None

        func = self.bv.get_function_at(target_addr)
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
        self,
        func_symbol: Union[Symbol, str],
        tainted_param: Union[Variable, SSAVariable],
        loc: MediumLevelILInstruction,
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
            function_model: FunctionModel = modeled_functions[
                get_modeled_function_index(func_symbol)
            ]
            if (
                function_model.taints_return or function_model.taint_destinations
            ) and tainted_param_in_model_sources(function_model, loc, tainted_param):
                return function_model

        # Analyze imported function
        if hasattr(func_symbol, "name"):
            func_symbol = func_symbol.name

        if self.libraries_mapped:
            for lib_name, lib_binary_view in self.libraries_mapped.items():
                for func in lib_binary_view.functions:
                    if func.name == func_symbol:
                        text_section = lib_binary_view.sections.get(".text")
                        for func in lib_binary_view.functions:
                            if text_section.start <= func.start < text_section.end:
                                if func_symbol in func.name.lower():
                                    return self.trace_function_taint(
                                        func, tainted_param, lib_binary_view
                                    )

        return None
