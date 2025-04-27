# vfa: Variable Flow Analysis
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


class Analysis:
    def __init__(self, binaryview, verbose=None, libraries_mapped: dict = None):
        self.bv = binaryview
        self.verbose = verbose
        self.libraries_mapped = libraries_mapped

        if self.verbose:
            self.is_function_param_tainted_printed = False

    def get_sliced_calls(
        self, data: list, func_name: str, propagated_vars: list
    ) -> dict | None:
        """
        This function will take slice data and output the tainted function calls

        Args:
            data (list[TaintedLOC]): Slice data from either of the tainted slices functions
            func_name (str): The name of the function we're doing analysis in
            propagated_vars (list[TaintedVar]): A list of all of the tainted variables

        Return:
            This function returns a dictionary with the key being the parent function name and LOC address and the data being
            the call name, the address of the function call, the LOC, and the parameter map
        """
        if self.verbose:
            raise TypeError(
                f"\n{Fore.LIGHTRED_EX}get_sliced_calls{Fore.RESET}({Fore.MAGENTA}self, data: list, func_name: str, verbose: list{Fore.RESET})\n{f'{Fore.GREEN}={Fore.RESET}' * 65}"
            )

        function_calls = {}

        for taintedloc in data:
            addr = taintedloc.addr
            loc = taintedloc.loc

            if int(loc.operation) == int(MediumLevelILOperation.MLIL_CALL):
                param_map = param_var_map(loc.params, propagated_vars)
                call_function_object = addr_to_func(self, int(str(loc.dest), 16))
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
    def tainted_forward_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        output: OutputMode = OutputMode.Returned,
    ) -> tuple[list, str, list[Variable]] | None:
        """
        This function will preform variable flow analysis on a variable or function parameter of interest (going forwards)

        Args:
            target (tuple[int, str]): A list of 2 inputs, the first being the address and the second being the variable name
            var_type (SlicingID): Defined if slicing a variable or a function parameter
            output (OutputMode): Type of output, can be returned or printed, default set to returned

        Returns:
            A tuple containing the sliced data, the function name, and the propagated variables
        """
        # if self.verbose:
        #     print(
        #         f"\n{Fore.LIGHTRED_EX}tainted_forward_slice{Fore.RESET}({Fore.MAGENTA}self, target: list[int, str], var_type: SlicingID, output: OutputMode = OutputMode.Returned{Fore.RESET})\n{f'{Fore.GREEN}={Fore.RESET}'*114}"
        #     )

        if hasattr(target.loc_address, "start"):
            func_obj = target.loc_address

        else:
            func_obj = addr_to_func(self, target.loc_address)
            if func_obj is None:
                print(
                    f"[{Fore.RED}Error{Fore.RESET}] Could not find a function containing address: {target.loc_address}"
                )
                return None

        sliced_func = {}
        propagated_vars = []

        # Start by tracing the initial target variable
        match var_type:
            # Handle case where the target var for slicing is a function var
            case SlicingID.FunctionVar:
                instr = func_obj.get_llil_at(target.loc_address)
                instr_mlil = instr.mlil
                instr_hlil = instr.hlil

                if instr_mlil:
                    var_object = str_to_var_object(target.variable, func_obj)

                    if var_object:
                        sliced_func, propagated_vars = trace_tainted_variable(
                            analysis=self,
                            function_object=func_obj,
                            mlil_loc=instr_mlil,
                            variable=var_object,
                            trace_type=SliceType.Forward,
                        )

                    else:
                        # handle Globals
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
                                    s = get_symbol_from_const_ptr(self, op)
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

                            sliced_func, propagated_vars = trace_tainted_variable(
                                analysis=self,
                                function_object=func_obj,
                                mlil_loc=instr_mlil,
                                variable=tainted_global,
                                trace_type=SliceType.Forward,
                            )

                        # handle struct member references/derefernces
                        else:
                            if instr_hlil.operation == int(
                                HighLevelILOperation.HLIL_ASSIGN
                            ):
                                destination = instr_hlil.dest

                                if destination.operation == int(
                                    HighLevelILOperation.HLIL_DEREF_FIELD
                                ):
                                    struct_offset = destination.offset
                                    base_expr = destination.src

                                    if base_expr.operation == int(
                                        HighLevelILOperation.HLIL_VAR
                                    ):
                                        base_var = base_expr.var
                                        tainted_struct_member = TaintedStructMember(
                                            loc_address=target.loc_address,
                                            member=target.variable,
                                            offset=struct_offset,
                                            hlil_var=base_var,
                                            variable=instr_mlil.dest.var,
                                            confidence_level=TaintConfidence.Tainted,
                                        )

                                        sliced_func, propagated_vars = (
                                            trace_tainted_variable(
                                                analysis=self,
                                                function_object=func_obj,
                                                mlil_loc=instr_mlil,
                                                variable=tainted_struct_member,
                                                trace_type=SliceType.Forward,
                                            )
                                        )

                            elif instr_mlil.operation == int(
                                MediumLevelILOperation.MLIL_SET_VAR
                            ):
                                struct_offset = instr_mlil.ssa_form.src.offset
                                source = instr_mlil.src
                                source_hlil = instr_hlil.src

                                if source.operation == int(
                                    MediumLevelILOperation.MLIL_LOAD_STRUCT
                                ):
                                    base_var = source_hlil.var
                                    tainted_struct_member = TaintedStructMember(
                                        loc_address=target.loc_address,
                                        member=target.variable,
                                        offset=struct_offset,
                                        hlil_var=base_var,
                                        variable=instr_mlil.src.src.var,
                                        confidence_level=TaintConfidence.Tainted,
                                    )

                                    sliced_func, propagated_vars = (
                                        trace_tainted_variable(
                                            analysis=self,
                                            function_object=func_obj,
                                            mlil_loc=instr_mlil,
                                            variable=tainted_struct_member,
                                            trace_type=SliceType.Forward,
                                        )
                                    )

                                elif source.operation == int(
                                    MediumLevelILOperation.MLIL_VAR_FIELD
                                ):
                                    #:TODO work on this, this is the struct field referencing
                                    pass

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
                    raise AttributeError(f"[{Fore.RED}Error{Fore.RESET}] Couldn't find the parameter reference")

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
    def tainted_backwards_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        output: OutputMode = OutputMode.Returned,
    ) -> tuple[list, str, list[Variable]] | None:
        """
        This function will preform variable flow analysis on a variable or variable of interest (going backwards).

        Args:
            target (tuple[int, str]): An integer and str representing the LOC address of the variable of interest and the str being the variable of interest.
            output (OutputMode): Results can be either printed back out or returned back for further analysis.

        Returns:
            A tuple containing the sliced data, the function name, and the propagated variables
        """
        if self.verbose:
            print(
                f"\n{Fore.LIGHTRED_EX}tainted_backwards_slice{Fore.RESET}({Fore.MAGENTA}self, target: list[int, str], output: OutputMode = OutputMode.Returned{Fore.RESET})\n{f'{Fore.GREEN}={Fore.RESET}'*104}"
            )

        func_obj = addr_to_func(self, target.loc_address)
        if func_obj is None:
            print(
                f"[{Fore.RED}Error{Fore.RESET}] Could not find a function containing address: {target.loc_address}"
            )
            return None

        if var_type == SlicingID.FunctionVar:
            instr_mlil = func_obj.get_llil_at(target.loc_address).mlil
            vars_in_loc = func_obj.vars
            var_to_trace = [var for var in vars_in_loc if var.name == target.variable][
                0
            ]
            print(var_to_trace)

            if var_to_trace:
                data, propagated_vars = trace_tainted_variable(
                    analysis=self,
                    function_object=func_obj,
                    variable=var_to_trace,
                    mlil_loc=instr_mlil,
                    trace_type=SliceType.Backward,
                )

            else:
                raise ValueError(
                    f"{Fore.RED}Couldn't find var_to_trace, you likely input the wrong address or variable name{Fore.RESET}"
                )

        elif var_type == SlicingID.FunctionParam:
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
                param_ref = func_obj.get_mlil_var_refs(target_param)
            except AttributeError:
                return None

            first_ref_addr = [
                i.address
                for i in param_ref
                if func_obj.get_llil_at(i.address).mlil is not None
            ][0]

            first_ref_mlil = func_obj.get_llil_at(first_ref_addr).mlil
            data, propagated_vars = trace_tainted_variable(
                analysis=self,
                function_object=func_obj,
                variable=target_param,
                mlil_loc=first_ref_mlil.address,
                trace_type=SliceType.Backward,
            )

        else:
            raise ValueError(
                f"[{Fore.RED}SlicingID invalid{Fore.RESET}], got {SlicingID}, expected valid {SlicingID}"
            )

        match output:
            case OutputMode.Returned:
                if self.verbose:
                    print(
                        f"Instruction Index | Address | LOC | Target Variable | Propagated Variable\n{'-'*53}"
                    )
                    for tainted_mlil in data:
                        print(tainted_mlil.loc.instr_index, tainted_mlil)

                return data, func_obj.name, propagated_vars

            case OutputMode.Printed:
                print(
                    f"\nInstruction Index | Address | LOC | Target Variable | Propagated Variable\n{'-'*53}"
                )
                for tainted_mlil in data:
                    print(tainted_mlil.loc.instr_index, tainted_mlil)

            case _:
                print(
                    f"[{Fore.RED}Error{Fore.RESET}] output must be either returned or printed"
                )
                return None

    @cache
    def complete_slice(
        self,
        target: TaintTarget,
        var_type: SlicingID,
        slice_type: SliceType,
        output: OutputMode = OutputMode.Returned,
    ) -> dict:
        """
        `complete_slice` Take an original Slice of the target function and then also slice the function calls.

        Args:
            target (tuple[int, str]): target is the LOC address or the function start address if slicing a function parameter and the string of the variable name or parameter
            var_type (SlicingID): Variable Type can be either a function parameter or function variable
            slice_type (SliceType): Type of slice being either forward or backward
            output (OutputMode): Output mode, data can be either returned or printed out to the screen

        Returns:
            Returns a dictionary of the data gathered being the function name as the key and then the slice data and propagated variables as the two pieces of data for each key
        """
        propagation_cache = {}
        propagated_vars = []
        calls_analyzed = []

        # Get the parent function "complete" slice and sliced calls
        if slice_type == SliceType.Forward:
            try:
                slice_data, og_func_name, propagated_vars = self.tainted_forward_slice(
                    target=target,
                    var_type=var_type,
                )

            except TypeError:
                raise TypeError(f"[{Fore.RED}ERROR{Fore.RESET}] Address is likely wrong in target | got: {target.loc_address:#0x} for {target.variable}")

        elif slice_type == SliceType.Backward:
            try:
                slice_data, og_func_name, propagated_vars = (
                    self.tainted_backwards_slice(
                        target=target,
                        var_type=var_type,
                    )
                )

            except TypeError:
                raise TypeError(
                    f"[{Fore.RED}ERROR{Fore.RESET}] Address is likely wrong in target | got: {target.loc_address:#0x} for {target.variable}"
                )

        else:
            raise TypeError(
                f"[{Fore.RED}ERROR{Fore.RESET}] forward_or_backward param must be a valid SliceType ( must be either backward or forward )"
            )

        sliced_calls = self.get_sliced_calls(slice_data, og_func_name, propagated_vars)

        # If sliced_calls returns None than we return the already gathered from the parent function, there are
        # no calls to analyze meaning that the target variable does not propagate out of the parent function
        parent_function_object = func_name_to_object(self, og_func_name)
        if sliced_calls == None:
            propagation_cache[
                og_func_name, str_to_var_object(target.variable, parent_function_object)
            ] = (
                slice_data,
                propagated_vars,
            )
            return propagation_cache

        # Push the first slice data from the parent function into the propagation cache
        propagation_cache[
            (og_func_name, str_to_var_object(target.variable, parent_function_object))
        ] = (slice_data, propagated_vars)

        imported_func_count = 0
        imported_functions = [
            i.name
            for i in self.bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
        ]

        for key, data in sliced_calls.items():
            if str(data[0]) in imported_functions:
                imported_func_count += 1

        # Get the variable flow from all the function calls it passed through from the original function:
        sliced_calls_to_analyze = {}
        sliced_calls_to_analyze.update(sliced_calls)

        if imported_func_count > 0:
            call_count = len(sliced_calls) - imported_func_count
        else:
            call_count = len(sliced_calls)

        while call_count > 0:
            new_calls = {}
            for key, data in sliced_calls_to_analyze.items():
                call_name = data[0]
                if call_name in imported_functions:
                    continue

                loc_addr = key[1]
                func_addr = data[1]
                param_map = data[3]
                func_param_to_analyze = None

                # slice the data at which that param is used in correlation with the parent variable and get sliced calls from the function to update sliced_calls_to_analyze
                for param_name, arg_num in param_map.items():
                    if param_name.var in [var.variable for var in propagated_vars]:
                        arg_pos = arg_num[1]
                        analyzed_key = (param_name, arg_num[1], call_name, loc_addr)
                        func_obj = addr_to_func(self, func_addr)

                        for index, param in enumerate(func_obj.parameter_vars):
                            index = index + 1
                            if index == arg_pos:
                                func_param_to_analyze = param

                        if analyzed_key in calls_analyzed:
                            continue

                        else:
                            calls_analyzed.append(analyzed_key)

                        if slice_type == SliceType.Forward:
                            new_slice_data, func_name, propagated_vars = (
                                self.tainted_forward_slice(
                                    target=TaintTarget(
                                        func_addr, func_param_to_analyze
                                    ),
                                    var_type=SlicingID.FunctionParam,
                                )
                            )

                        elif slice_type == SliceType.Backward:
                            new_slice_data, func_name, propagated_vars = (
                                self.tainted_backwards_slice(
                                    target=TaintTarget(
                                        func_addr, func_param_to_analyze
                                    ),
                                    var_type=SlicingID.FunctionParam,
                                )
                            )

                        new_sliced_calls = self.get_sliced_calls(
                            new_slice_data, call_name, propagated_vars
                        )

                        if (
                            func_name,
                            func_param_to_analyze,
                        ) not in propagation_cache.keys() or (
                            func_name,
                            func_param_to_analyze.name,
                        ) not in propagation_cache.keys():
                            propagation_cache[(func_name, func_param_to_analyze)] = (
                                new_slice_data,
                                propagated_vars,
                            )

                        if new_sliced_calls != None:
                            call_count += len(new_sliced_calls)
                            new_calls.update(new_sliced_calls)

            call_count -= 1
            sliced_calls_to_analyze.update(new_calls)

        match output:
            case OutputMode.Returned:
                if self.verbose:
                    for key, (s_data, _) in propagation_cache.items():
                        function_name, tainted_var = key
                        if isinstance(tainted_var, str):
                            print(
                                f"Function name: {function_name} | Target Variable: {tainted_var} | Address | LOC | Target Variable | Propagated Variable\n{(Fore.LIGHTGREEN_EX+'='+Fore.RESET)*(91 + len(function_name) + len(tainted_var))}"
                            )
                        elif isinstance(tainted_var, Variable):
                            print(
                                f"\nFunction name: {function_name} | Target Variable: {tainted_var.name} | Address | LOC | Target Variable | Propagated Variable\n{(Fore.LIGHTGREEN_EX+'='+Fore.RESET)*(91 + len(function_name) + len(tainted_var.name))}"
                            )

                        for tainted_loc in s_data:
                            print(tainted_loc)

                return propagation_cache

            case OutputMode.Printed:
                for key, (s_data, _) in propagation_cache.items():
                    if isinstance(tainted_var, str):
                        print(
                            f"\nFunction name: {function_name} | Target Variable: {tainted_var} | Address | LOC | Target Variable | Propagated Variable\n{(Fore.LIGHTGREEN_EX+'='+Fore.RESET)*(91 + len(function_name) + len(tainted_var))}"
                        )
                    elif isinstance(tainted_var, Variable):
                        print(
                            f"\nFunction name: {function_name} | Target Variable: {tainted_var.name} | Address | LOC | Target Variable | Propagated Variable\n{(Fore.LIGHTGREEN_EX+'='+Fore.RESET)*(91 + len(function_name) + len(tainted_var.name))}"
                        )

                    for tainted_loc in s_data:
                        print(tainted_loc)

    def is_function_param_tainted(
        self,
        function_node: int | Function,
        tainted_params: Variable | str | list[Variable],
        origin_function: Function = None,
        original_tainted_params: Variable | str | list[Variable] = None,
    ):
        """
        Determine if a function's parameter is tainted by tracking the tainted parameter's path and analyzing
        whether it influences other parameter paths.

        Args:
            function_node (int | Function): The target function, specified either by its starting address (int)
                                                or as a Binary Ninja Function object.
            tainted_params (Variable | str | list[Variable]): The parameter(s) to check for taint. This can be a single
                                                            Variable object, a string representing the parameter name,
                                                            or a list of Variable objects.
            origin_function (Function): This parameter is used for internal tracking and paremeter matching (do not touch this parameter).

        Returns:
            set: A set of parameter names (as strings) that are determined to be tainted within the function (including your inputted list of parameters).
            bool: Whether or not the return variable is tainted
        """

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
            function_node = addr_to_func(self, function_node)
            if function_node is None:
                raise Exception(
                    f"Could not find target function from address @ {addr:#0x}"
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

        if self.verbose and not self.is_function_param_tainted_printed:
            print(
                # f"\n{Fore.LIGHTRED_EX}is_function_param_tainted{Fore.RESET}({Fore.MAGENTA}self, function_node: int | Function, "
                f"tainted_params: Variable | str | list[Variable]{Fore.RESET})\n-> {Fore.LIGHTBLUE_EX}{function_node}"
                f"{Fore.RESET}:{Fore.BLUE}{tainted_params}{Fore.RESET}\n{Fore.GREEN}{'='*113}{Fore.RESET}"
            )
            self.is_function_param_tainted_printed = True

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
                            function_node.start,
                        )
                    )
                except ValueError:
                    continue

            elif isinstance(param, Variable):
                tainted_variables.add(
                    TaintedVar(
                        param,
                        TaintConfidence.Tainted,
                        function_node.start,
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
                            address_variable = loc.dest.operands[0]

                        elif len(loc.dest.operands) == 2:
                            address_variable, offset_variable = loc.dest.operands
                            addr_var, offset = address_variable.operands

                        if offset_variable:
                            offset_var_taintedvar = [
                                var.variable
                                for var in variable_mapping
                                if var.variable == offset_variable
                            ]

                        if offset_var_taintedvar:
                            tainted_variables.add(
                                TaintedAddressOfField(
                                    variable=addr_var or address_variable,
                                    offset=offset,
                                    offset_var=offset_var_taintedvar,
                                    confidence_level=TaintConfidence.Tainted,
                                    loc_address=loc.address,
                                    targ_function=function_node,
                                )
                            )

                        else:
                            tainted_variables.add(
                                TaintedAddressOfField(
                                    variable=addr_var or address_variable,
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

                    # Check if the instruction is a function call in SSA form
                    case int(MediumLevelILOperation.MLIL_CALL_SSA):
                        # Extract the parameters involved in the call
                        call_params = [
                            param
                            for param in loc.params
                            if isinstance(param, MediumLevelILVarSsa)
                        ]

                        call_object = addr_to_func(self, int(str(loc.dest), 16))

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

                        interproc_results = self.is_function_param_tainted(
                            call_object,
                            tainted_sub_params,
                            origin_function,
                            original_tainted_params,
                        )

                        # Map back the tainted sub-function parameters to the current function's variables
                        tainted_sub_variables = [
                            param[0].ssa_form.var
                            for param in zipped_params
                            if param[1].name in interproc_results.tainted_param_names
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
                        tainted_variables.add(
                            TaintedVar(
                                written_var,
                                TaintConfidence.Tainted,
                                loc.address,
                            )
                        )

        # Extract underlying variables from TaintedVar before walking the mapping.
        underlying_tainted = {tv.variable for tv in tainted_variables}

        # Determine all parameters that are tainted by walking through the variable mapping.
        tainted_parameters.update(
            var
            for var in walk_variable(variable_mapping, underlying_tainted)
            if var.name in [param.name for param in origin_function.parameter_vars]
        )

        # Find out if return variable is tainted
        ret_variable_tainted = False

        for t_var in tainted_variables:
            loc = origin_function.get_llil_at(t_var.loc_address)
            """
                Checking variable use sites for each variable in the tainted variables set, 
                if any of them are the return variable, the return variable is tainted.
            """
            if loc:
                var_use_sites = t_var.variable.use_sites

                for use_site in var_use_sites:
                    if isinstance(use_site, MediumLevelILRet):
                        ret_variable_tainted = True

        # DEBUG
        # pprint(variable_mapping)
        # pprint(tainted_variables)

        #:TODO map the params to which param tainted it.
        return InterprocTaintResult(
            tainted_param_names=tainted_parameters,
            # tainted_param_map={},
            original_tainted_variables=original_tainted_params,
            is_return_tainted=ret_variable_tainted,
        )

    def is_function_imported(self, instr_mlil: MediumLevelILInstruction) -> bool:
        if instr_mlil.operation != MediumLevelILOperation.MLIL_CALL:
            return False

        call_dest = instr_mlil.dest
        if call_dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            func_address = call_dest.constant
        else:
            return False

        target_symbol = self.bv.get_symbol_at(func_address)
        if not target_symbol:
            return False

        if target_symbol.type == SymbolType.ImportedFunctionSymbol.value:
            return target_symbol

        else:
            return False

    def analyze_imported_function(self, func_symbol):
        for _, lib_binary_view in self.libraries_mapped.items():
            for function in lib_binary_view.functions:
                if function.name == func_symbol.name:
                    print("AAAA", function.mlil)
