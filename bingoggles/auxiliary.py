from binaryninja.variable import Variable
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    MediumLevelILAddressOfField,
    MediumLevelILLoad,
    MediumLevelILConstPtr,
    MediumLevelILVar,
)
from binaryninja.highlevelil import HighLevelILOperation, HighLevelILInstruction
from colorama import Fore
from .bingoggles_types import *
from binaryninja.enums import MediumLevelILOperation, SymbolType


def flat(ops):
    flat_list = []
    for op in ops:
        if isinstance(op, list):
            flat_list.extend(flat(op))
        elif isinstance(op, HighLevelILInstruction):
            flat_list.append(op)
            # only flatten first-level children, don't recurse beyond
            for child in op.operands:
                if isinstance(child, HighLevelILInstruction):
                    flat_list.append(child)
        else:
            flat_list.append(op)
    return flat_list


def get_symbol_from_const_ptr(bv, const_ptr: MediumLevelILConstPtr):
    # data_symbol_type_val = int(SymbolType.DataSymbol)

    for symbol in [
        s for s in bv.get_symbols() if int(s.type) == int(SymbolType.DataSymbol)
    ]:
        if symbol.address == const_ptr.value:
            return symbol
    return None


def get_struct_field_refs(bv, tainted_struct_member: TaintedStructMember):
    def traverse_operand(op):
        if not isinstance(op, HighLevelILInstruction):
            return False

        if (
            op.operation
            in {
                int(HighLevelILOperation.HLIL_DEREF_FIELD),
                int(HighLevelILOperation.HLIL_STRUCT_FIELD),
            }
            and op.offset == tainted_struct_member.offset
        ):
            return True

        return False

    hlil_use_sites = set()
    # func_object = analysis.get_functions_containing(
    #     tainted_struct_member.loc_address
    # )[0]
    func_object = bv.get_functions_containing(tainted_struct_member.loc_address)[0]
    var_refs_hlil = func_object.get_hlil_var_refs(tainted_struct_member.hlil_var)
    var_refs_mlil = func_object.get_mlil_var_refs(tainted_struct_member.variable)

    for ref in var_refs_hlil:
        instr = func_object.get_llil_at(ref.address).hlil
        operands = flat(instr.operands)
        for op in operands:
            if traverse_operand(op):
                hlil_use_sites.add(instr)
                break

    mlil_use_sites = []
    mlil_use_sites.extend(
        [func_object.get_llil_at(i.address).mlil for i in hlil_use_sites]
    )
    mlil_use_sites.extend(var_refs_mlil)
    return mlil_use_sites


def param_var_map(params, propagated_vars: list[TaintedVar]) -> dict:
    """
    `param_var_map` This function is used within the `get_sliced_calls` function to get a parameter variable map of the propagated variables used within a call

    Args:
        params: list of the parameters in the function call
        propagated_vars: list tainted variables

    Returns:
        returns a dictionary of the call information regarding the propagated parameters
        param: (parameter index, parameter position index)
    """
    param_info = {}
    param_index = 0

    for param in params:
        str_param = str(param)
        param_pos_index = params.index(param) + 1

        for var in propagated_vars:
            if str(var.variable) == str_param:
                param_index += 1
                if str_param not in param_info:
                    param_info[param] = (param_index, param_pos_index)

        param_index = 0

    return param_info


def addr_to_func(bv, address: int) -> Function | None:
    """
    `addr_to_func` Get the function object from an address

    Args:
        address (int): address to the start or within the function object

    Returns:
        Binary ninja function object
    """
    function_object = bv.get_functions_containing(address)
    if function_object:
        return function_object[0]

    else:
        return None


def func_name_to_object(analysis, func_name: str) -> int | None:
    """
    `func_name_to_object` Get a function address from a name

    Args:
        func_name (str): function name

    Returns:
        Binary ninja function object
    """
    for func in analysis.bv.functions:
        if func.name == func_name:
            return func
    else:
        raise ValueError(
            f"[{Fore.RED}Error] could not find function object for the function name {func_name}"
        )


def is_address_of_field_offset_match(
    mlil_instr: MediumLevelILInstruction, var_to_trace: TaintedAddressOfField
):
    """
    Checks if the given instruction's destination or source contains an address of
    field with the same variable `var_to_trace`.

    This function analyzes both the destination and source of the provided instruction
    (`mlil_instr`). If either contains an address of field with a matching variable
    `var_to_trace`, it returns True. Otherwise, it returns False.

    Args:
        mlil_instr (MediumLevelILInstruction): The instruction to analyze, which
                                                contains destination and source operands.
        var_to_trace (TaintedAddressOfField): The tainted variable containing the offset
                                                to match against the instruction's operands.

    Returns:
        bool: True if the offset in the instruction matches the offset of `var_to_trace`,
              otherwise False.
    """
    destination, source = mlil_instr.dest, mlil_instr.src

    if isinstance(destination, list):
        for d in destination:
            if isinstance(d, MediumLevelILAddressOfField):
                offset = d.offset
                if offset == var_to_trace.offset:
                    return True

    elif isinstance(destination, MediumLevelILAddressOfField):
        offset = destination.offset
        if offset == var_to_trace.offset:
            return True

    if isinstance(source, list):
        for s in source:
            if isinstance(s, MediumLevelILAddressOfField):
                offset = s.offset
                if offset == var_to_trace.offset:
                    return True

    elif isinstance(source, MediumLevelILAddressOfField):
        offset = source.offset
        if offset == var_to_trace.offset:
            return True

    return False


def get_struct_field_name(loc: MediumLevelILInstruction):
    #:TODO this will not work in production, beacuse we need to account for nested structs, etc etc, this should be more robust
    if loc.operation == int(MediumLevelILOperation.MLIL_SET_VAR):
        return loc.tokens[4]

    elif loc.operation == int(MediumLevelILOperation.MLIL_STORE_STRUCT):
        return loc.tokens[2]

    else:
        raise ValueError(
            f"[Error] Could not find struct member name\n[LOC (unhandled)]: {loc}"
        )


def trace_tainted_variable(
    analysis,
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    variable: Variable | TaintedGlobal | TaintedVar | TaintedStructMember,
    trace_type: SliceType,
) -> tuple[list, list] | None:
    """
    Trace the usage and propagation of a tainted variable within a given function's MLIL (Medium Level IL).

    Depending on the specified trace direction (forward or backward), this function will analyze how
    a tainted variable propagates through MLIL instructions, collecting relevant locations and variables
    encountered during the analysis.

    Args:
        analysis: The analysis object providing context and utilities for taint tracking.
        function_object (Function): The Binary Ninja function object where the variable resides.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction where the tainted variable was initially found.
        variable (Variable): The Binary Ninja variable object to be traced.
        trace_type (SliceType): Indicates the direction of the trace (SliceType.Forward or SliceType.Backward).

    Returns:
        tuple[list, list] | None:
            - A tuple containing two lists:
                1. List of TaintedLOC objects representing MLIL instructions where the variable was used or affected.
                2. List of TaintedVar (or TaintedAddressOfField) objects that were traced during the analysis.
            - Returns None if the trace cannot be performed (e.g., variable not found or invalid trace type).
    """
    collected_locs: list[TaintedLOC] = []
    already_iterated: list = []
    glob_refs_memoized = {}

    def get_mlil_glob_refs(
        function_object: Function, var_to_trace: TaintedGlobal
    ) -> list:
        """
        Finds all MLIL instructions that reference a given global variable.

        This function identifies and collects use sites of a `TaintedGlobal` object by scanning
        all MLIL instructions in the specified function. It ensures accurate matches by validating
        symbol references and filtering false positives.

        Args:
            analysis (Analysis): The analysis context containing the Binary Ninja BinaryView.
            function_object (Function): The function in which to search for global variable references.
            var_to_trace (TaintedGlobal): The global variable to track in the function.

        Returns:
            list: A list of MLIL instructions that reference `var_to_trace`.
        """
        variable_use_sites = []
        if var_to_trace.variable in glob_refs_memoized.keys():
            return glob_refs_memoized[var_to_trace.variable]

        for instr_mlil in function_object.mlil.instructions:
            for op in flat(instr_mlil.operands):
                if isinstance(op, MediumLevelILConstPtr):
                    symbol = get_symbol_from_const_ptr(analysis.bv, op)
                    if symbol and symbol.name == var_to_trace.variable:
                        variable_use_sites.append(instr_mlil)

        glob_refs_memoized[var_to_trace.variable] = variable_use_sites
        return variable_use_sites

    def get_connected_var(
        function_object: Function,
        target_variable: (
            TaintedVar | TaintedGlobal | TaintedAddressOfField | TaintedStructMember
        ),
    ) -> Variable | None:
        """
        Tries to find the source variable (vars_read) that most recently assigned to the given target variable.
        """
        connected_candidates = []

        if isinstance(target_variable, (TaintedVar, TaintedAddressOfField)):
            refs = function_object.get_mlil_var_refs(target_variable.variable)

            for ref in refs:
                mlil = function_object.get_llil_at(ref.address).mlil
                if not mlil:
                    continue

                if (
                    mlil.vars_written
                    and mlil.vars_written[0] == target_variable.variable
                    and mlil.vars_read
                ):
                    connected_candidates.append((mlil.address, mlil.vars_read[0]))

        elif isinstance(target_variable, TaintedGlobal):
            refs = get_mlil_glob_refs(function_object, target_variable)

            for ref in refs:
                mlil = function_object.get_llil_at(ref.address).mlil
                if not mlil:
                    continue

                if (
                    mlil.vars_written
                    and mlil.vars_written[0] == target_variable.variable
                    and mlil.vars_read
                ):
                    connected_candidates.append((mlil.address, mlil.vars_read[0]))

        elif isinstance(target_variable, TaintedStructMember):
            # Struct members may propagate from field access or assignment
            refs = get_struct_field_refs(function_object.view, target_variable)

            for ref in refs:
                mlil = function_object.get_llil_at(ref.address).mlil
                if not mlil:
                    continue

                if hasattr(mlil, "vars_read") and mlil.vars_read:
                    connected_candidates.append((mlil.address, mlil.vars_read[0]))

        if connected_candidates:
            # Return the one closest to the target variable (highest address before its use)
            return sorted(connected_candidates, key=lambda t: t[0], reverse=True)[0][1]

        return None

    # initialize the vars_found list if variable type is TaintedVar or binja Variable
    if isinstance(variable, TaintedVar) or isinstance(variable, Variable):
        if isinstance(mlil_loc, int):
            vars_found: list = [TaintedVar(variable, TaintConfidence.Tainted, mlil_loc)]

        else:
            vars_found: list = [
                TaintedVar(variable, TaintConfidence.Tainted, mlil_loc.address)
            ]

    # initialzie the vars_found list if the variable type is TaintedGlobal
    elif isinstance(variable, TaintedGlobal):
        vars_found: list = [variable]

    # initialize the vars_found list if the variable type is TaintedStructMember
    elif isinstance(variable, TaintedStructMember):
        vars_found: list = [variable]

    else:
        raise ValueError(
            f"[{Fore.RED}ERROR{Fore.RESET}] Could not find variable with that name.",
            variable,
            type(variable),
        )

    def get_var_name(v):
        if isinstance(v, TaintedGlobal):
            return v.variable

        elif isinstance(v, TaintedStructMember):
            return str(v.member)

        else:
            return v.variable.name

    while vars_found:
        var_to_trace = vars_found.pop(0)
        addresses = [i.addr for i in collected_locs]
        var_name = get_var_name(var_to_trace)

        if var_name in [get_var_name(var) for var in already_iterated]:
            continue

        already_iterated.append(var_to_trace)

        if isinstance(var_to_trace, TaintedGlobal):
            variable_use_sites = get_mlil_glob_refs(function_object, var_to_trace)

        elif isinstance(var_to_trace, TaintedStructMember):
            variable_use_sites = get_struct_field_refs(analysis.bv, var_to_trace)

        else:
            variable_use_sites = function_object.get_mlil_var_refs(
                var_to_trace.variable
            )

        for ref in variable_use_sites:
            instr_mlil = function_object.get_llil_at(ref.address).mlil
            if not instr_mlil:
                continue

            if trace_type == SliceType.Forward:
                if collected_locs and instr_mlil.instr_index < mlil_loc.instr_index:
                    continue

            elif trace_type == SliceType.Backward:
                if collected_locs and instr_mlil.instr_index > mlil_loc.instr_index:
                    continue

            if instr_mlil.address in addresses:
                continue

            if isinstance(var_to_trace, TaintedAddressOfField):
                if not is_address_of_field_offset_match(instr_mlil, var_to_trace):
                    continue

            match int(instr_mlil.operation):
                case int(MediumLevelILOperation.MLIL_STORE_STRUCT):
                    struct_offset = instr_mlil.ssa_form.offset
                    instr_hlil = function_object.get_llil_at(instr_mlil.address).hlil

                    if instr_hlil.operation == int(HighLevelILOperation.HLIL_ASSIGN):
                        lhs = instr_hlil.dest

                        if lhs.operation == int(HighLevelILOperation.HLIL_DEREF_FIELD):
                            struct_offset = lhs.offset
                            base_expr = lhs.src

                            if base_expr.operation == int(
                                HighLevelILOperation.HLIL_VAR
                            ):
                                base_var = base_expr.var
                                tainted_struct_member = TaintedStructMember(
                                    loc_address=instr_hlil.address,
                                    member=get_struct_field_name(instr_mlil),
                                    offset=struct_offset,
                                    hlil_var=base_var,
                                    variable=instr_mlil.dest.var,
                                    confidence_level=TaintConfidence.Tainted,
                                )

                                vars_found.append(tainted_struct_member)

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
                                loc_address=instr_mlil.address,
                                member=get_struct_field_name(instr_mlil),
                                offset=struct_offset,
                                hlil_var=base_var,
                                variable=instr_mlil.src.src.var,
                                confidence_level=TaintConfidence.Tainted,
                            )

                            vars_found.append(tainted_struct_member)

                    tainted_loc = TaintedLOC(
                        instr_mlil,
                        instr_mlil.address,
                        var_to_trace,
                        get_connected_var(
                            function_object=function_object,
                            target_variable=var_to_trace,
                        ),
                        var_to_trace.confidence_level,
                        function_object=function_object,
                    )

                    collected_locs.append(tainted_loc)

                case int(MediumLevelILOperation.MLIL_STORE):
                    address_variable, offset_variable = None, None
                    offset_var_taintedvar = None
                    addr_var = None
                    offset = None

                    if len(instr_mlil.dest.operands) == 1:
                        address_variable = instr_mlil.dest.operands[0]

                    elif len(instr_mlil.dest.operands) == 2:
                        address_variable, offset_variable = instr_mlil.dest.operands
                        addr_var, offset = address_variable.operands

                        offset_var_taintedvar = [
                            var.variable
                            for var in already_iterated
                            if var.variable == offset_variable
                        ]

                    if offset_var_taintedvar:
                        vars_found.append(
                            TaintedAddressOfField(
                                variable=addr_var or address_variable,
                                offset=offset,
                                offset_var=offset_var_taintedvar,
                                confidence_level=TaintConfidence.Tainted,
                                loc_address=instr_mlil.address,
                                targ_function=function_object,
                            )
                        )

                    else:
                        vars_found.append(
                            TaintedAddressOfField(
                                variable=addr_var or address_variable,
                                offset=offset,
                                offset_var=TaintedVar(
                                    variable=offset_variable,
                                    confidence_level=TaintConfidence.NotTainted,
                                    loc_address=instr_mlil.address,
                                ),
                                confidence_level=TaintConfidence.Tainted,
                                loc_address=instr_mlil.address,
                                targ_function=function_object,
                            )
                        )

                    # Add other cases where the above wouldn't be sufficient i guess if any.
                    tainted_loc = TaintedLOC(
                        instr_mlil,
                        instr_mlil.address,
                        var_to_trace,
                        get_connected_var(
                            function_object=function_object,
                            target_variable=var_to_trace,
                        ),
                        var_to_trace.confidence_level,
                        function_object=function_object,
                    )

                    collected_locs.append(tainted_loc)

                # Handle the case that we get a MLIL_CALL and we want to essentially taint the data passed into it or assigned from it
                # variables tainted here are marked with "maybe" as the confidence level.
                case int(MediumLevelILOperation.MLIL_CALL):
                    imported_function = analysis.is_function_imported(instr_mlil)
                    if imported_function:
                        analysis.analyze_imported_function(imported_function)

                    if instr_mlil.params:
                        parameters_tainted = []
                        tainted_call_params = []

                        params_mapped, tainted_func_param = (
                            get_func_param_from_call_param(
                                analysis.bv, instr_mlil, var_to_trace
                            )
                        )
                        call_func_object = addr_to_func(
                            analysis.bv, int(str(instr_mlil.dest), 16)
                        )

                        if call_func_object:
                            interproc_results = analysis.is_function_param_tainted(
                                function_node=call_func_object,
                                tainted_params=tainted_func_param,
                            )

                            if analysis.verbose:
                                analysis.is_function_param_tainted_printed = False

                            if (
                                interproc_results.is_return_tainted
                                and instr_mlil.vars_written
                            ):
                                for var_assigned in instr_mlil.vars_written:
                                    vars_found.append(
                                        TaintedVar(
                                            var_assigned,
                                            TaintConfidence.Tainted,
                                            instr_mlil.address,
                                        )
                                    )

                            if interproc_results.tainted_param_names:
                                for call_param, func_param in params_mapped.items():
                                    for (
                                        tainted_func_param
                                    ) in interproc_results.tainted_param_names:
                                        if func_param.name == tainted_func_param:
                                            parameters_tainted.append(call_param)

                                    for param in parameters_tainted:
                                        try:
                                            tainted_call_params.append(
                                                TaintedVar(
                                                    param.var,
                                                    var_to_trace.confidence_level,
                                                    instr_mlil.address,
                                                )
                                            )

                                        except AttributeError:
                                            glob_symbol = get_symbol_from_const_ptr(
                                                analysis.bv, param
                                            )

                                            tainted_call_params.append(
                                                TaintedGlobal(
                                                    glob_symbol.name,
                                                    var_to_trace.confidence_level,
                                                    instr_mlil.address,
                                                    param,
                                                    glob_symbol,
                                                )
                                            )

                                    vars_found.extend(tainted_call_params)

                    tainted_loc = TaintedLOC(
                        instr_mlil,
                        instr_mlil.address,
                        var_to_trace,
                        get_connected_var(
                            function_object=function_object,
                            target_variable=var_to_trace,
                        ),
                        var_to_trace.confidence_level,
                        function_object=function_object,
                    )

                    collected_locs.append(tainted_loc)

                case int(MediumLevelILOperation.MLIL_SET_VAR):
                    if isinstance(instr_mlil.src, MediumLevelILLoad) or isinstance(
                        instr_mlil.dest, MediumLevelILLoad
                    ):
                        if isinstance(instr_mlil.src, MediumLevelILLoad):
                            try:
                                address_variable, offset_variable = instr_mlil.src.vars_read

                            except ValueError:
                                address_variable = instr_mlil.src.vars_read[0]
                                offset_variable = None

                            except Exception as e:
                                print("[LOC (unhandled)]: ", instr_mlil, hex(instr_mlil.address))
                                print("[Error]: ", e)
                                continue

                        else:
                            address_variable, offset_variable = (
                                instr_mlil.dest.vars_written
                            )

                        offset_var_taintedvar = [
                            var.variable
                            for var in already_iterated
                            if var.variable == offset_variable
                        ]

                        if offset_var_taintedvar:
                            vars_found.append(
                                TaintedAddressOfField(
                                    variable=address_variable,
                                    offset=None,
                                    offset_var=offset_var_taintedvar[0],
                                    confidence_level=var_to_trace.confidence_level,
                                    loc_address=instr_mlil.address,
                                    targ_function=function_object,
                                )
                            )
                            if (
                                offset_var_taintedvar[0].confidence_level
                                == TaintConfidence.Tainted
                                and var_to_trace.confidence_level
                                == TaintConfidence.Tainted
                                or var_to_trace.confidence_level
                                == TaintConfidence.MaybeTainted
                            ):
                                if instr_mlil.vars_written:
                                    for variable_written_to in instr_mlil.vars_written:
                                        vars_found.append(
                                            TaintedVar(
                                                variable_written_to,
                                                var_to_trace.confidence_level,
                                                instr_mlil.address,
                                            )
                                        )

                            else:
                                if instr_mlil.vars_written:
                                    for variable_written_to in instr_mlil.vars_written:
                                        vars_found.append(
                                            TaintedVar(
                                                variable_written_to,
                                                TaintConfidence.MaybeTainted,
                                                instr_mlil.address,
                                            )
                                        )

                        else:
                            vars_found.append(
                                TaintedAddressOfField(
                                    variable=address_variable,
                                    offset=None,
                                    offset_var=TaintedVar(
                                        variable=offset_variable,
                                        confidence_level=TaintConfidence.NotTainted,
                                        loc_address=instr_mlil.address,
                                    ),
                                    confidence_level=var_to_trace.confidence_level,
                                    loc_address=instr_mlil.address,
                                    targ_function=function_object,
                                )
                            )

                    if instr_mlil.vars_written:
                        for variable_written_to in instr_mlil.vars_written:
                            vars_found.append(
                                TaintedVar(
                                    variable_written_to,
                                    var_to_trace.confidence_level,
                                    instr_mlil.address,
                                )
                            )

                    if instr_mlil.vars_read:
                        connected_variable = get_connected_var(
                            function_object, var_to_trace
                        )
                        if connected_variable:
                            vars_found.append(
                                TaintedVar(
                                    connected_variable,
                                    var_to_trace.confidence_level,
                                    instr_mlil.address,
                                )
                            )

                    tainted_loc = TaintedLOC(
                        instr_mlil,
                        instr_mlil.address,
                        var_to_trace,
                        get_connected_var(
                            function_object=function_object,
                            target_variable=var_to_trace,
                        ),
                        var_to_trace.confidence_level,
                        function_object=function_object,
                    )

                    collected_locs.append(tainted_loc)

                case int(MediumLevelILOperation.MLIL_SET_VAR_FIELD):
                    dest_var = instr_mlil.dest

                    tainted_loc = TaintedLOC(
                        instr_mlil,
                        instr_mlil.address,
                        var_to_trace,
                        get_connected_var(
                            function_object=function_object,
                            target_variable=var_to_trace,
                        ),
                        var_to_trace.confidence_level,
                        function_object=function_object,
                    )

                    collected_locs.append(tainted_loc)
                    vars_found.append(
                        TaintedVar(
                            dest_var, TaintConfidence.Tainted, instr_mlil.address
                        )
                    )

                case _:
                    print(
                        f"[INFO] we hit an un-accounted for case, here are some details\n[MLIL Operation] {instr_mlil.operation.name}\n[LOC]: {instr_mlil}\n [Address] {instr_mlil.address:#0x}\n\n"
                    )
                    # Collect vars written
                    if instr_mlil.vars_written:
                        for variable_written_to in instr_mlil.vars_written:
                            try:
                                vars_found.append(
                                    TaintedVar(
                                        variable_written_to,
                                        TaintConfidence.Tainted,
                                        instr_mlil.address,
                                    )
                                )

                            except AttributeError:
                                glob_symbol = get_symbol_from_const_ptr(
                                    analysis.bv, param
                                )

                                tainted_call_params.append(
                                    TaintedGlobal(
                                        glob_symbol.name,
                                        var_to_trace.confidence_level,
                                        instr_mlil.address,
                                        param,
                                        glob_symbol,
                                    )
                                )

                    tainted_loc = TaintedLOC(
                        instr_mlil,
                        instr_mlil.address,
                        var_to_trace,
                        get_connected_var(
                            function_object=function_object,
                            target_variable=var_to_trace,
                        ),
                        var_to_trace.confidence_level,
                        function_object=function_object,
                    )

                    collected_locs.append(tainted_loc)

    if trace_type == SliceType.Forward:
        sorted_locs = sorted(collected_locs, key=lambda i: i.loc.instr_index)
        seen = set()
        sorted_locs = [
            i for i in sorted_locs if not (i.addr in seen or seen.add(i.addr))
        ]

        return sorted_locs, already_iterated

    elif trace_type == SliceType.Backward:
        sorted_locs = sorted(
            collected_locs, key=lambda i: i.loc.instr_index, reverse=True
        )
        seen = set()
        sorted_locs = [
            i for i in sorted_locs if not (i.addr in seen or seen.add(i.addr))
        ]

        return sorted_locs, already_iterated


def find_param_by_name(func_obj: Function, param_name: str) -> Variable:
    """
    `find_param_by_name` find a function parameter by name

    Args:
        func_obj (Function): target binja function object
        param_name (str): target parameter name to get back

    Returns:
        returns back a param variable object.
    """
    var_object = None
    for param in func_obj.parameter_vars:
        if param.name == param_name:
            var_object = param

    if var_object:
        return var_object

    else:
        raise ValueError(
            f"[{Fore.RED}Param '{param_name}' not found{Fore.RESET}] Please try passing a valid parameter name for the given function"
        )


def str_param_to_var_object(
    function_object: Function, var_name: str, ssa_form: bool = False
):
    """
    Get the variable object for a parameter in a function based on a string variable name.

    Args:
        function_object (Function): Binary Ninja function object.
        var_name (str): Name of the variable as a string.
        ssa_form (bool): Whether to return the SSA form of the variable.

    Returns:
        Variable or SSAVariable: The corresponding variable object.
    """
    if ssa_form:
        # Access the Medium Level IL (MLIL) SSA form of the function
        mlil_ssa = function_object.mlil.ssa_form
        if mlil_ssa is None:
            raise ValueError(
                f"SSA form is not available for function {function_object.name}"
            )

        # Iterate through SSA variables to find the matching one
        for ssa_var in mlil_ssa.ssa_vars:
            if ssa_var.var.name == var_name:
                return ssa_var

        raise ValueError(
            f"SSA form of variable '{var_name}' not found in function {function_object.name}"
        )

    else:
        # Access the regular parameters of the function
        parameters = function_object.parameter_vars
        for param in parameters:
            if param.name == var_name:
                return param

        raise ValueError(
            f"Parameter '{var_name}' not found in function {function_object.name}"
        )


def str_to_var_object(
    var_as_str: str | MediumLevelILVar, function_object: Function
) -> Variable | None:
    var_object = None

    if isinstance(var_as_str, MediumLevelILVar):
        var_as_str = var_as_str.name

    for var in function_object.vars:
        if var.name == var_as_str:
            var_object = var

    return var_object


def get_func_param_from_call_param(bv, instr_mlil, var_to_trace):
    """
    Maps the parameters of a called function to the arguments provided at the call site and identifies which function parameter corresponds to a given variable.

    Args:
        bv: BinaryView object representing the binary being analyzed.
        instr_mlil: The Medium Level Intermediate Language (MLIL) instruction representing the function call.
        var_to_trace: The variable (as a TaintedVar object) from the calling function that we want to trace into the called function.

    Returns:
        tuple: A tuple containing:
            - mapped (dict): A dictionary mapping each call argument (MLIL variable) to its corresponding function parameter (Variable object).
            - tainted_func_param (Variable or None): The function parameter that corresponds to the provided variable (`var_to_trace`). Returns None if no match is found.

    Example:
        Suppose we have a function call `foo(a, b)` in the MLIL, and we want to determine which parameter of `foo` corresponds to the variable `a` in the caller.

        ```python
        mapped_params, tainted_param = get_func_param_from_call_param(analysis, instr_mlil, var_to_trace)
        ```

        Here, `mapped_params` will be a dictionary where the keys are the MLIL variables representing the arguments (`a` and `b`), and the values are the corresponding parameters of `foo`. `tainted_param` will be the parameter of `foo` that corresponds to `a`.

    Notes:
        - This function assumes that the destination of the call (`instr_mlil.dest`) can be resolved to a function address.
        - The function retrieves the `Function` object corresponding to the called function's address.
        - It then maps each argument at the call site to the corresponding parameter of the called function.
        - Finally, it checks if any of the call arguments match the `var_to_trace` and returns the corresponding function parameter.
    """
    function_object = addr_to_func(bv, int(str(instr_mlil.dest), 16))
    if function_object:
        call_params = instr_mlil.params
        function_params = [i for i in function_object.parameter_vars]
        mapped = dict(zip(call_params, function_params))

        var_object = var_to_trace.variable

        tainted_func_param = None

        for call_param, func_param in mapped.items():
            if hasattr(call_param, "var") and call_param.var == var_object:
                tainted_func_param = func_param

        return mapped, tainted_func_param

    else:
        return None, None
