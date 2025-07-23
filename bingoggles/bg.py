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
                output_bndb_path = self.bv.file.original_filename + ".bndb" if not self.bv.file.original_filename.endswith(".bndb") else self.bv.file.original_filename
        
        success = self.bv.file.create_database(output_bndb_path, None, None)
        if success:
            print(f"Successfully saved BinaryView to {output_bndb_path}")
        else:
            print(f"Failed to save BinaryView to {output_bndb_path}")

    def resolve_and_patch(self, resolved: List[FunctionModel], function_object: Function, mlil_loc: MediumLevelILInstruction) -> Union[FunctionModel, None]:
        """
        Resolve and patch a modeled variadic function call if it matches a known model.

        Args:
            resolved (List[FunctionModel]): A list of already resolved function models to avoid duplicates.
            function_object (Function): The Binary Ninja function object containing the call.
            mlil_loc (MediumLevelILInstruction): The MLIL instruction representing the function call.

        Returns:
            FunctionModel or None: The resolved function model if a new one was found and patched, otherwise None.
        """
        section = self.bv.get_sections_at(function_object.start)
        if section:
            name = section[0].name
            if name == ".synthetic_builtins":
                return None

        model = resolve_modeled_variadic_function(function_object, mlil_loc)
        if model and model not in resolved:
            patch_function_params(function_object, mlil_loc, model)
            resolved.append(model)
            return model

        return None

    def is_in_text_section(self, function_object: Function) -> bool:
        """
        Check if the given function is located within the .text section of the binary.

        Args:
            function_object (Function): The Binary Ninja function object to check.

        Returns:
            bool: True if the function is in the .text section, False otherwise.
        """
        text_section = self.bv.sections.get(".text")
        if not text_section:
            return False

        function_start_address = function_object.start
        text_section_start = text_section.start
        text_section_end = text_section.end

        return text_section_start <= function_start_address < text_section_end

    def resolve_varg_func_calls(self, functions_to_resolve: list = [], output_path: str = None) -> None:
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

        for function_object in iterator:
            if self.is_in_text_section(function_object): 
                for block in function_object.medium_level_il:
                    for mlil_loc in block:
                        if isinstance(mlil_loc, MediumLevelILCall):
                            self.resolve_and_patch(resolved, function_object, mlil_loc)

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
            - render_sliced_output(...): Render the output of a taint slice for visualization or further analysis.
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
            tuple[list[TaintedLOC], list[TaintedVar]]:
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
            tuple[list[TaintedLOC], list[TaintedVar]]:
                - A list of tainted code locations (TaintedLOC) where taint propagation was detected.
                - A list of all propagated variables (TaintedVar) found during the trace.
        """
        symbol = [
            s
            for s in self.bv.get_symbols()
            if int(s.type) == int(SymbolType.DataSymbol) and s.name == target.variable
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
            tuple[list[TaintedLOC], list[TaintedVar]]:
                - A list of tainted code locations (TaintedLOC) where taint propagation was detected.
                - A list of all propagated variables (TaintedVar) found during the trace.
        """
        instr_hlil = func_obj.get_llil_at(target.loc_address).hlil

        try:
            struct_offset = instr_mlil.ssa_form.src.offset
        except AttributeError:
            struct_offset = instr_mlil.ssa_form.offset

        if instr_hlil.operation == int(HighLevelILOperation.HLIL_ASSIGN):
            destination = instr_hlil.dest

            if destination.operation == int(HighLevelILOperation.HLIL_DEREF_FIELD):
                struct_offset = destination.offset
                base_expr = destination.src

                if base_expr.operation == int(HighLevelILOperation.HLIL_VAR):
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

        elif instr_mlil.operation == int(MediumLevelILOperation.MLIL_SET_VAR):
            source = instr_mlil.src
            base_var = instr_mlil.src.src
            if source.operation == int(MediumLevelILOperation.MLIL_LOAD_STRUCT):
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

            elif source.operation == int(MediumLevelILOperation.MLIL_VAR_FIELD):
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
            tuple[list[TaintedLOC], list[TaintedVar]]:
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

    def render_sliced_output(
        self,
        sliced_func: Union[dict, list],
        output_mode: OutputMode,
        func_obj: Function,
        propagated_vars: list,
    ):
        """
        Renders or returns the output of a sliced function based on the specified output mode.

        Args:
            sliced_func (dict): A mapping from keys (usually address/function) to lists of TaintedLOC or TaintedVar.
            output_mode (OutputMode): Specifies how to present the output.
            func_obj (Function): The function object being analyzed.
            propagated_vars (list): List of propagated variables (TaintedVar objects).

        Returns:
            tuple | None: Returns a tuple of (tainted_locs, func_name, propagated_vars) when `Returned`, otherwise None.
        """
        if output_mode == OutputMode.Printed:
            print(
                f"Address | LOC | Target Variable | Propagated Variable | Taint Confidence\n{(Fore.LIGHTGREEN_EX+'-'+Fore.RESET)*72}"
            )
            for i in sliced_func:
                print(i.loc.instr_index, i)

        elif output_mode == OutputMode.Returned:
            if self.verbose:
                print(
                    f"Address | LOC | Target Variable | Propagated Variable | Taint Confidence\n{(Fore.LIGHTGREEN_EX+'-'+Fore.RESET)*72}"
                )
                for i in sliced_func:
                    print(i.loc.instr_index, i)

            return [i for i in sliced_func], func_obj.name, propagated_vars

        else:
            raise TypeError(
                f"[{Fore.RED}ERROR{Fore.RESET}] output_mode must be either OutputMode.Printed or OutputMode.Returned"
            )

    @cache
    def tainted_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        output: OutputMode = OutputMode.Returned,
        slice_type: SliceType = SliceType.Forward,
    ) -> Union[tuple[list, str, list[Variable]], None]:
        """
        Run a forward or backward taint analysis slice from a given variable..

        Traces the propagation of a target variable (local, global, struct member, or function parameter)
        within a single function, using either forward or backward slicing. Returns the list of tainted
        instructions, the function name, and the propagated variables.

        Args:
            target (TaintTarget): The variable or memory location to start slicing from.
            var_type (SlicingID): The type of the target (FunctionVar, GlobalVar, StructMember, FunctionParam).
            output (OutputMode, optional): Whether to print or return the slice results. Default is Returned.
            slice_type (SliceType, optional): Slicing direction (Forward or Backward). Default is Forward.
            
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
                print(
                    f"[{Fore.RED}Error{Fore.RESET}] Could not find a function containing address: {target.loc_address:#0x}"
                )
                return None

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
            self.render_sliced_output(
                sliced_func, OutputMode.Printed, func_obj, propagated_vars
            )
        
        elif output == OutputMode.Returned:
            tainted_locs, func_name, tainted_vars = self.render_sliced_output(
                sliced_func, OutputMode.Returned, func_obj, propagated_vars
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
        tainted_params: Tuple[Union[Variable, str, Tuple[Variable]]],
        binary_view: BinaryView = None,
        origin_function: Function = None,
        original_tainted_params: Tuple[Union[Variable, str, list[Variable]]] = None,
        tainted_param_map: dict = None,
        recursion_limit=8,
        sub_functions_analyzed=0,
    ) -> InterprocTaintResult:
        """
        Perform interprocedural taint analysis to determine whether any parameters or the return value
        of a function are tainted, directly or indirectly.

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
                                    addr_var,
                                    offset,
                                    TaintedVar(
                                        offset_variable,
                                        TaintConfidence.NotTainted,
                                        loc.address,
                                    ),
                                    TaintConfidence.Tainted,
                                    loc.address,
                                    function_node,
                                )
                            )

                        else:
                            tainted_variables.add(
                                TaintedVarOffset(
                                    (
                                        addr_var
                                        if isinstance(addr_var, Variable)
                                        else addr_var
                                    ),
                                    offset,
                                    None,
                                    TaintConfidence.Tainted,
                                    loc.address,
                                    function_node,
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

                        call_object = addr_to_func(
                            binary_view,
                            instr.dest.value.value,
                        )

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
                        if loc.operation in [
                            int(MediumLevelILOperation.MLIL_RET),
                            int(MediumLevelILOperation.MLIL_GOTO),
                            int(MediumLevelILOperation.MLIL_IF),
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

        # Determine all parameters that are tainted by walking through the variable mapping.
        for var in walk_variable(variable_mapping, underlying_tainted):
            if isinstance(var, MediumLevelILVarSsa):
                var = var.var

            if var.name not in [param.name for param in origin_function.parameter_vars]:
                continue

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
