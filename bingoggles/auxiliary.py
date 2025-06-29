from binaryninja.variable import Variable
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    MediumLevelILAddressOfField,
    MediumLevelILLoad,
    MediumLevelILConstPtr,
    MediumLevelILVar,
    MediumLevelILConst,
)
from binaryninja.highlevelil import HighLevelILOperation, HighLevelILInstruction
from colorama import Fore
from typing import Sequence, Dict, Tuple, Optional, Union
from bingoggles_types import *
from binaryninja.enums import MediumLevelILOperation, SymbolType
from binaryninja import BinaryView, Symbol
from functools import cache


def flat(
    ops: Sequence[Union[HighLevelILInstruction, MediumLevelILInstruction]]
) -> List[Union[HighLevelILInstruction, MediumLevelILInstruction]]:
    """
    Flatten a nested sequence of operands, preserving HighLevelILInstruction instances
    and including their immediate child instructions.

    This function will:
    - Recursively expand any nested lists found in `ops`.
    - Append any `HighLevelILInstruction` in `ops`.
    - For each `HighLevelILInstruction`, also append its direct operands
      that are themselves `HighLevelILInstruction` objects.
    - Append any other non-list operands as-is.

    Args:
        ops (Sequence[Union[HighLevelILInstruction, MediumLevelILInstruction]]): A sequence of operands which may include nested lists, arbitrary objects, or `HighLevelILInstruction` instances.

    Returns:
        A flat list where:
        - Nested lists from the original `ops` are expanded one level deep (recursively).
        - All `HighLevelILInstruction` objects are included.
        - Any direct child `HighLevelILInstruction` operands of those instructions are also included.
        - All other operands are carried through unchanged.
    """
    flat_list = []
    for op in ops:
        if isinstance(op, list):
            flat_list.extend(flat(op))
        elif isinstance(op, HighLevelILInstruction):
            flat_list.append(op)
            for child in op.operands:
                if isinstance(child, HighLevelILInstruction):
                    flat_list.append(child)
        else:
            flat_list.append(op)
    return flat_list


@cache
def get_symbol_from_const_ptr(
    bv: BinaryView, const_ptr: MediumLevelILConstPtr
) -> Optional[Symbol]:
    """
    Resolve a const-pointer operand back to its data symbol.

    Args:
        bv (BinaryView):        The BinaryView containing your symbols.
        const_ptr (MediumLevelILConstPtr): An MLIL ConstPtr whose .value is the address of some data.

    Returns:
        The matching Symbol of type DataSymbol, or None if not found.
    """
    for symbol in [
        s for s in bv.get_symbols() if int(s.type) == int(SymbolType.DataSymbol)
    ]:
        if symbol.address == const_ptr.value:
            return symbol
    return None


@cache
def get_struct_field_refs(
    bv: BinaryView, tainted_struct_member: TaintedStructMember
) -> List[MediumLevelILInstruction]:
    """
    Retrieve all MLIL instructions that access a specific struct member field.

    This function scans the MLIL of the function containing the provided struct member taint,
    identifying instructions that read from or write to the specific field.

    Args:
        bv (BinaryView):
            The BinaryView object containing the binary analysis state.
        tainted_struct_member (TaintedStructMember):
            The struct member of interest, containing:
                - loc_address (int): address where the field was first tainted.
                - member (str): name of the struct field.
                - offset (int): byte offset of the field within the struct.
                - hlil_var (Variable): HLIL variable representing the base struct object.
                - variable (Variable): MLIL variable representing the struct base in MLIL.
                - confidence_level (TaintConfidence): confidence level of taint propagation.

    Returns:
        List[MediumLevelILInstruction]:
            A list of MLIL instructions that access (read or write) the specified struct member field.
    """
    func_object = bv.get_functions_containing(tainted_struct_member.loc_address)[0]
    mlil_use_sites = set()
    struct_ops = [
        int(MediumLevelILOperation.MLIL_LOAD_STRUCT),
        int(MediumLevelILOperation.MLIL_VAR_FIELD),
        int(MediumLevelILOperation.MLIL_STORE_STRUCT),
    ]

    for block in func_object.mlil:
        for instr_mlil in block:
            if (
                instr_mlil.operation in struct_ops
                or hasattr(instr_mlil, "src")
                and hasattr(instr_mlil.src, "operation")
                and instr_mlil.src.operation in struct_ops
            ):
                if instr_mlil.operation == int(
                    MediumLevelILOperation.MLIL_STORE_STRUCT
                ):
                    if instr_mlil.offset == tainted_struct_member.offset:
                        mlil_use_sites.add(instr_mlil)

                elif instr_mlil.src.operation == int(
                    MediumLevelILOperation.MLIL_LOAD_STRUCT
                ):
                    if instr_mlil.src.offset == tainted_struct_member.offset:
                        mlil_use_sites.add(instr_mlil)

                elif instr_mlil.src.operation == int(
                    MediumLevelILOperation.MLIL_VAR_FIELD
                ):
                    if instr_mlil.src.offset == tainted_struct_member.offset:
                        mlil_use_sites.add(instr_mlil)

    return list(mlil_use_sites)


def param_var_map(
    params: List[MediumLevelILVar], propagated_vars: List[TaintedVar]
) -> Dict[MediumLevelILVar, Tuple[int, int]]:
    """
    Build a map of MLIL call parameters that correspond to your propagated taint variables.

    Scans each `param` in order and, if it matches one of your `propagated_vars`, assigns:
      - the “match count” (1-based increment as you discover matches), and
      - the parameter's position in the argument list (also 1-based).

    Args:
        params:   The list of MLIL call-site parameters.
        propagated_vars:   The list of `TaintedVar` instances you've already discovered.

    Returns:
        A dict where each key is a `param` that matched a `propagated_var`, and the
        value is a `(match_count, param_position_index)` tuple.
    """
    param_info: Dict[MediumLevelILVar, Tuple[int, int]] = {}
    for pos, param in enumerate(params, start=1):
        for idx, tv in enumerate(propagated_vars, start=1):
            if str(param) == str(tv.variable):
                # only record the first match per param
                if param not in param_info:
                    param_info[param] = (idx, pos)
                break
    return param_info


def addr_to_func(bv: BinaryView, address: int) -> Function | None:
    """
    `addr_to_func` Get the function object from an address

    Args:
        bv: (BinaryView): Binary Ninja BinaryView
        address (int): address to the start or within the function object

    Returns:
        Binary ninja function object
    """
    function_object = bv.get_functions_containing(address)
    if function_object:
        return function_object[0]

    else:
        return None


def func_name_to_object(bv: BinaryView, func_name: str) -> int | None:
    """
    `func_name_to_object` Get a function address from a name

    Args:
        func_name (str): function name
        bv (BinaryView): Binary Ninja BinaryView

    Returns:
        Binary ninja function object
    """
    for func in bv.functions:
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
    """
    Extract the struct field name token from an MLIL instruction.

    This helper inspects the instruction's operation and returns the token
    corresponding to the struct member's name.

    Args:
        loc (MediumLevelILInstruction): The MLIL instruction that performs a struct
            field assignment or store.

    Returns:
        str: The name of the struct field referenced in the instruction tokens.
    """
    if loc.operation == int(MediumLevelILOperation.MLIL_SET_VAR):
        return loc.tokens[-1].text

    elif loc.operation == int(MediumLevelILOperation.MLIL_STORE_STRUCT):
        field_name_index = next(
            (i for i, t in enumerate(loc.tokens) if t.text == " = "), None
        )
        return loc.tokens[field_name_index - 1].text

    raise ValueError(f"[Error] Could not find struct member name in LOC: {loc}")


@cache
def get_mlil_glob_refs(
    analysis, function_object: Function, var_to_trace: TaintedGlobal
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
    if var_to_trace.variable in analysis.glob_refs_memoized.keys():
        return analysis.glob_refs_memoized[var_to_trace.variable]

    for instr_mlil in function_object.mlil.instructions:
        for op in flat(instr_mlil.operands):
            if isinstance(op, MediumLevelILConstPtr):
                symbol = get_symbol_from_const_ptr(analysis.bv, op)
                if symbol and symbol.name == var_to_trace.variable:
                    variable_use_sites.append(instr_mlil)

    analysis.glob_refs_memoized[var_to_trace.variable] = variable_use_sites
    return variable_use_sites


def is_rw_operation(instr_mlil: MediumLevelILInstruction):
    """
    Determines if the given Medium Level IL instruction represents a read or write operation.

    A read/write operation includes direct variable reads, writes, memory accesses, and address-of operations.
    This function also checks the `src` and `dest` sub-instructions (if present) to ensure the full expression
    chain is composed of read/write operations.

    Parameters:
        instr_mlil (MediumLevelILInstruction): The MLIL instruction to analyze.

    Returns:
        bool: True if the instruction and its relevant subexpressions are read/write operations, False otherwise.
    """
    read_write_ops = [
        int(MediumLevelILOperation.MLIL_SET_VAR),
        int(MediumLevelILOperation.MLIL_SET_VAR_ALIASED),
        int(MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD),
        int(MediumLevelILOperation.MLIL_SET_VAR_FIELD),
        int(MediumLevelILOperation.MLIL_SET_VAR_SPLIT),
        int(MediumLevelILOperation.MLIL_LOAD),
        int(MediumLevelILOperation.MLIL_LOAD_STRUCT),
        int(MediumLevelILOperation.MLIL_STORE),
        int(MediumLevelILOperation.MLIL_STORE_STRUCT),
        int(MediumLevelILOperation.MLIL_VAR),
        int(MediumLevelILOperation.MLIL_VAR_ALIASED),
        int(MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD),
        int(MediumLevelILOperation.MLIL_VAR_FIELD),
        int(MediumLevelILOperation.MLIL_VAR_SPLIT),
        int(MediumLevelILOperation.MLIL_VAR_PHI),
        int(MediumLevelILOperation.MLIL_MEM_PHI),
        int(MediumLevelILOperation.MLIL_ADDRESS_OF),
        int(MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD),
    ]

    def op_is_rw(il):
        return hasattr(il, "operation") and int(il.operation) in read_write_ops

    if not op_is_rw(instr_mlil):
        return False

    if hasattr(instr_mlil, "src") and not op_is_rw(instr_mlil.src):
        return False

    if hasattr(instr_mlil, "dest") and not op_is_rw(instr_mlil.dest):
        return False

    return True


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
            refs = get_mlil_glob_refs(analysis, function_object, target_variable)

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

        elif isinstance(v, TaintedAddressOfField):
            return v.name

        else:
            return v.variable.name

    while vars_found:
        var_to_trace = vars_found.pop(
            0
        )  # pop a var to trace off of the vars_found list
        var_name = get_var_name(
            var_to_trace
        )  # variable name of the current variable we're tracing

        # never trace the same variable twice
        if var_name in [get_var_name(var) for var in already_iterated]:
            continue

        # since we are tracing a new variable, we're going to append to the already_iterated list
        already_iterated.append(var_to_trace)

        # Exact the variable use sites for the target variable to trace
        if isinstance(var_to_trace, TaintedGlobal):
            variable_use_sites = get_mlil_glob_refs(
                analysis, function_object, var_to_trace
            )

        elif isinstance(var_to_trace, TaintedStructMember):
            variable_use_sites = get_struct_field_refs(analysis.bv, var_to_trace)

        else:
            variable_use_sites = function_object.get_mlil_var_refs(
                var_to_trace.variable
            )

        # iterate over each variable reference
        for ref in variable_use_sites:
            instr_mlil = function_object.get_llil_at(ref.address).mlil
            # print("mlil: ", instr_mlil, var_to_trace)
            if (
                not instr_mlil
            ):  # if we cannot resolve the instr mlil then we skip the reference
                continue

            # make sure that we're either going backwards or forwards depending on what the caller of the function specified in arguments
            if trace_type == SliceType.Forward:
                if collected_locs and instr_mlil.instr_index < mlil_loc.instr_index:
                    continue
                if (
                    instr_mlil.instr_index
                    < function_object.get_llil_at(
                        var_to_trace.loc_address
                    ).mlil.instr_index
                ):
                    continue

            elif trace_type == SliceType.Backward:
                if collected_locs and instr_mlil.instr_index > mlil_loc.instr_index:
                    continue

            # see if the var to trace is used as a pointer to an array or something, typical for MLIL_STORE/MLIL_LOAD type operations
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
                        addr_var = instr_mlil.dest.operands[0]

                    elif len(instr_mlil.dest.operands) == 2:
                        address_variable, offset_variable = instr_mlil.dest.operands
                        if isinstance(offset_variable, MediumLevelILConst):
                            addr_var, offset = instr_mlil.dest.operands
                            offset_variable = None
                        else:
                            addr_var, offset = address_variable.operands

                        if offset_variable:
                            offset_var_taintedvar = [
                                var.variable
                                for var in already_iterated
                                if var.variable == offset_variable
                            ]

                    if offset_var_taintedvar:
                        vars_found.append(
                            TaintedAddressOfField(
                                variable=(
                                    addr_var
                                    if isinstance(addr_var, Variable)
                                    else addr_var.var
                                ),
                                offset=offset,
                                offset_var=offset_var_taintedvar,
                                confidence_level=TaintConfidence.Tainted,
                                loc_address=instr_mlil.address,
                                targ_function=function_object,
                            )
                        )

                    elif offset_variable:
                        try:
                            vars_found.append(
                                TaintedAddressOfField(
                                    variable=address_variable,
                                    offset=offset,
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

                        except AttributeError:
                            glob_symbol = get_symbol_from_const_ptr(
                                analysis.bv, variable_written_to
                            )
                            if glob_symbol:
                                vars_found.append(
                                    TaintedAddressOfField(
                                        variable=address_variable,
                                        offset=offset,
                                        offset_var=TaintedGlobal(
                                            glob_symbol.name,
                                            TaintConfidence.NotTainted,
                                            instr_mlil.address,
                                            variable_written_to,
                                            glob_symbol,
                                        ),
                                        confidence_level=var_to_trace.confidence_level,
                                        loc_address=instr_mlil.address,
                                        targ_function=function_object,
                                    )
                                )

                    else:
                        vars_found.append(
                            TaintedAddressOfField(
                                variable=(
                                    addr_var
                                    if isinstance(addr_var, Variable)
                                    else addr_var.var
                                ),
                                offset=offset,
                                offset_var=None,
                                confidence_level=TaintConfidence.Tainted,
                                loc_address=instr_mlil.address,
                                targ_function=function_object,
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

                case int(MediumLevelILOperation.MLIL_CALL):
                    if instr_mlil.params:
                        imported_function = analysis.resolve_function_type(instr_mlil)

                        if imported_function:
                            #:TODO How can this be improved? when analyzing functions with complex variable arguments this will fail to analyze effectively (i think, not tested extensively yet for that)
                            func_analyzed = analysis.analyze_function_taint(
                                imported_function, var_to_trace
                            )

                            tainted_variables_to_add = set()
                            if func_analyzed and isinstance(
                                func_analyzed, FunctionModel
                            ):
                                # Handle vararg functions
                                if func_analyzed.taints_varargs:
                                    try:
                                        dest_tainted = [
                                            i.var if hasattr(i, "var") else None
                                            for i in instr_mlil.params
                                        ].index(
                                            var_to_trace.variable
                                        ) > func_analyzed.vararg_start_index
                                    except ValueError:
                                        dest_tainted = None

                                    if dest_tainted:
                                        vararg_indexes = [
                                            getattr(i, "var", None)
                                            for i in instr_mlil.params[
                                                func_analyzed.vararg_start_index :
                                            ]
                                        ]

                                        tainted_vararg_indexes = []

                                        for idx, var in enumerate(
                                            vararg_indexes,
                                            start=func_analyzed.vararg_start_index,
                                        ):
                                            if var is None:
                                                continue

                                            if var == var_to_trace.variable or var in [
                                                v.variable for v in already_iterated
                                            ]:
                                                tainted_vararg_indexes.append(idx + 1)

                                        if tainted_vararg_indexes:
                                            for t_src_indx in vararg_indexes:
                                                for (
                                                    t_dst_indx
                                                ) in func_analyzed.taint_destinations:
                                                    tainted_variables_to_add.add(
                                                        instr_mlil.params[t_dst_indx]
                                                    )

                                    for t_var in tainted_variables_to_add:
                                        try:
                                            vars_found.append(
                                                TaintedVar(
                                                    t_var.var,
                                                    var_to_trace.confidence_level,
                                                    instr_mlil.address,
                                                )
                                            )
                                        except AttributeError:
                                            glob_symbol = get_symbol_from_const_ptr(
                                                analysis.bv, t_var
                                            )
                                            if glob_symbol:
                                                vars_found.append(
                                                    TaintedGlobal(
                                                        glob_symbol.name,
                                                        var_to_trace.confidence_level,
                                                        instr_mlil.address,
                                                        t_var.var,
                                                        glob_symbol,
                                                    )
                                                )

                                    if func_analyzed.taints_return:
                                        for t_var in instr_mlil.vars_written:
                                            vars_found.append(
                                                TaintedVar(
                                                    t_var,
                                                    TaintConfidence.Tainted,
                                                    instr_mlil.address,
                                                )
                                            )

                                # Handle none vararg functions
                                else:
                                    for t_src_indx in func_analyzed.taint_sources:
                                        for (
                                            t_dst_indx
                                        ) in func_analyzed.taint_destinations:
                                            tainted_variables_to_add.add(
                                                instr_mlil.params[t_dst_indx]
                                            )

                                    if func_analyzed.taints_return:
                                        for t_var in instr_mlil.vars_written:
                                            vars_found.append(
                                                TaintedVar(
                                                    t_var,
                                                    TaintConfidence.Tainted,
                                                    instr_mlil.address,
                                                )
                                            )

                            elif func_analyzed and isinstance(
                                func_analyzed, InterprocTaintResult
                            ):
                                zipped_results = list(
                                    zip(
                                        func_analyzed.tainted_param_names,
                                        instr_mlil.params,
                                    )
                                )

                                for src_func_param, var in zipped_results:
                                    if var.var != var_to_trace.variable:
                                        vars_found.append(
                                            TaintedVar(
                                                var.var,
                                                TaintConfidence.Tainted,
                                                instr_mlil.address,
                                            )
                                        )

                                if func_analyzed.is_return_tainted:
                                    for t_var in instr_mlil.vars_written:
                                        vars_found.append(
                                            TaintedVar(
                                                t_var,
                                                TaintConfidence.Tainted,
                                                instr_mlil.address,
                                            )
                                        )

                        else:
                            tainted_call_params = []

                            _, tainted_func_param = get_func_param_from_call_param(
                                analysis.bv, instr_mlil, var_to_trace
                            )

                            call_func_object = addr_to_func(
                                analysis.bv, int(str(instr_mlil.dest), 16)
                            )

                            if call_func_object:
                                interproc_results = analysis.trace_function_taint(
                                    function_node=call_func_object,
                                    tainted_params=tainted_func_param,
                                    binary_view=analysis.bv,
                                )

                                if analysis.verbose:
                                    analysis.trace_function_taint_printed = False

                                if (
                                    interproc_results.is_return_tainted
                                    and instr_mlil.vars_written
                                ):
                                    for var_assigned in instr_mlil.vars_written:
                                        vars_found.append(
                                            TaintedVar(
                                                var_assigned,
                                                var_to_trace.confidence_level,
                                                instr_mlil.address,
                                            )
                                        )

                                if interproc_results.tainted_param_names:
                                    zipped_results = list(
                                        zip(
                                            interproc_results.tainted_param_names,
                                            instr_mlil.params,
                                        )
                                    )

                                    for src_func_param, var in zipped_results:
                                        if var.var != var_to_trace.variable:
                                            try:
                                                tainted_call_params.append(
                                                    TaintedVar(
                                                        var.var,
                                                        var_to_trace.confidence_level,
                                                        instr_mlil.address,
                                                    )
                                                )

                                            except AttributeError:
                                                glob_symbol = get_symbol_from_const_ptr(
                                                    analysis.bv, var
                                                )

                                                tainted_call_params.append(
                                                    TaintedGlobal(
                                                        glob_symbol.name,
                                                        var_to_trace.confidence_level,
                                                        instr_mlil.address,
                                                        var,
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
                                address_variable, offset_variable = (
                                    instr_mlil.src.vars_read
                                )

                            except ValueError:
                                address_variable = instr_mlil.src.vars_read[0]
                                offset_variable = None

                            except Exception as e:
                                print(
                                    "[LOC (unhandled)]: ",
                                    instr_mlil,
                                    hex(instr_mlil.address),
                                )
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
                                        try:
                                            vars_found.append(
                                                TaintedVar(
                                                    variable_written_to,
                                                    var_to_trace.confidence_level,
                                                    instr_mlil.address,
                                                )
                                            )

                                        except AttributeError:
                                            glob_symbol = get_symbol_from_const_ptr(
                                                analysis.bv, variable_written_to
                                            )
                                            if glob_symbol:
                                                vars_found.append(
                                                    TaintedGlobal(
                                                        glob_symbol.name,
                                                        var_to_trace.confidence_level,
                                                        instr_mlil.address,
                                                        variable_written_to,
                                                        glob_symbol,
                                                    )
                                                )
                            else:
                                if instr_mlil.vars_written:
                                    for variable_written_to in instr_mlil.vars_written:
                                        try:
                                            vars_found.append(
                                                TaintedVar(
                                                    variable_written_to,
                                                    TaintConfidence.MaybeTainted,
                                                    instr_mlil.address,
                                                )
                                            )

                                        except AttributeError:
                                            glob_symbol = get_symbol_from_const_ptr(
                                                analysis.bv, variable_written_to
                                            )
                                            if glob_symbol:
                                                vars_found.append(
                                                    TaintedGlobal(
                                                        glob_symbol.name,
                                                        TaintConfidence.MaybeTainted,
                                                        instr_mlil.address,
                                                        variable_written_to,
                                                        glob_symbol,
                                                    )
                                                )

                        else:
                            for variable_written_to in instr_mlil.vars_written:
                                try:
                                    vars_found.append(
                                        TaintedVar(
                                            variable_written_to,
                                            var_to_trace.confidence_level,
                                            instr_mlil.address,
                                        )
                                    )

                                except AttributeError:
                                    glob_symbol = get_symbol_from_const_ptr(
                                        analysis.bv, variable_written_to
                                    )
                                    if glob_symbol:
                                        vars_found.append(
                                            TaintedGlobal(
                                                glob_symbol.name,
                                                TaintConfidence.MaybeTainted,
                                                instr_mlil.address,
                                                variable_written_to,
                                                glob_symbol,
                                            )
                                        )

                    elif instr_mlil.vars_written:
                        for variable_written_to in instr_mlil.vars_written:
                            try:
                                vars_found.append(
                                    TaintedVar(
                                        variable_written_to,
                                        var_to_trace.confidence_level,
                                        instr_mlil.address,
                                    )
                                )

                            except AttributeError:
                                glob_symbol = get_symbol_from_const_ptr(
                                    analysis.bv, variable_written_to
                                )
                                if glob_symbol:
                                    vars_found.append(
                                        TaintedGlobal(
                                            glob_symbol.name,
                                            TaintConfidence.MaybeTainted,
                                            instr_mlil.address,
                                            variable_written_to,
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
                    if instr_mlil.vars_written and is_rw_operation(instr_mlil):
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
                                    analysis.bv, variable_written_to
                                )

                                tainted_call_params.append(
                                    TaintedGlobal(
                                        glob_symbol.name,
                                        var_to_trace.confidence_level,
                                        instr_mlil.address,
                                        variable_written_to,
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
