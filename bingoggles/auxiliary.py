from binaryninja.variable import Variable
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    MediumLevelILAddressOfField,
    MediumLevelILLoad,
    MediumLevelILConstPtr,
    MediumLevelILVar,
    MediumLevelILConst,
    MediumLevelILAddressOf,
)
from binaryninja.highlevelil import HighLevelILOperation, HighLevelILInstruction
from colorama import Fore
from typing import Sequence, Dict, Tuple, Optional, Union
from .bingoggles_types import *
from binaryninja.enums import MediumLevelILOperation, SymbolType
from binaryninja import BinaryView, Symbol
from functools import cache
from .function_registry import get_modeled_function_name_at_callsite


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
    bv: BinaryView, const_ptr: Union[MediumLevelILConstPtr, Variable, MediumLevelILVar]
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
        if symbol.address == const_ptr.value.value:
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
    mlil_instr: MediumLevelILInstruction, var_to_trace: TaintedVarOffset
) -> bool:
    """
    Checks if the given instruction's destination or source contains an address of
    field with the same variable `var_to_trace`.

    This function analyzes both the destination and source of the provided instruction
    (`mlil_instr`). If either contains an address of field with a matching variable
    `var_to_trace`, it returns True. Otherwise, it returns False.

    Args:
        mlil_instr (MediumLevelILInstruction): The instruction to analyze, which
                                                contains destination and source operands.
        var_to_trace (TaintedVarOffset): The tainted variable containing the offset
                                                to match against the instruction's operands.

    Returns:
        bool: True if the offset in the instruction matches the offset of `var_to_trace`,
              otherwise False.
    """
    destination, source = mlil_instr.dest, (
        mlil_instr.src if hasattr(mlil_instr, "src") else None
    )

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

        # review these operations
        int(MediumLevelILOperation.MLIL_VAR_ALIASED),
        int(MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD),
        int(MediumLevelILOperation.MLIL_VAR_PHI),
        
        int(MediumLevelILOperation.MLIL_MEM_PHI),
        int(MediumLevelILOperation.MLIL_ADDRESS_OF),
        int(MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD),
        
    ]

    def op_is_rw(il):
        return hasattr(il, "operation") and int(il.operation) in read_write_ops

    if not op_is_rw(instr_mlil):
        return False

    return True


def get_connected_var(
    analysis,
    function_object: Function,
    target_variable: Union[
        TaintedVar, TaintedGlobal, TaintedVarOffset, TaintedStructMember
    ],
) -> Union[Variable, None]:
    """
    Identifies the most recent source variable that was assigned to the given target variable.

    This function analyzes MLIL instructions within the specified function to locate the
    most recent assignment (typically via `MLIL_SET_VAR`, `MLIL_STORE`, or struct assignment)
    that propagated data into the `target_variable`. This is useful in backward dataflow
    analysis to trace the origin of a variable's value, or in forward slicing to map propagation
    chains.

    Args:
        analysis (Analysis): The analysis engine instance that provides context and utilities.
        function_object (Function): Binary Ninja function object where the variable is located.
        target_variable (TaintedVar | TaintedGlobal | TaintedVarOffset | TaintedStructMember):
            The variable whose source (vars_read) should be located.

    Returns:
        Variable | None:
            - The source variable from which the target variable most recently received its value.
            - None if no such assignment was found or the propagation path cannot be determined.
    """
    connected_candidates = []

    if isinstance(target_variable, (TaintedVar, TaintedVarOffset)):
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


def init_vars_found(
    mlil_loc: Union[MediumLevelILInstruction, int],
    variable: Union[
        TaintedVar, Variable, TaintedStructMember, TaintedStructMember, TaintedVarOffset
    ],
) -> list:
    """
    Initializes the taint tracking list with the appropriate representation of the target variable.

    This helper function determines how to wrap the input `variable` based on its type and
    returns it in a list as a starting point for taint propagation analysis. If the variable is
    a plain Binary Ninja `Variable`, it is converted into a `TaintedVar` with taint confidence.
    Otherwise, if the input is already a wrapped taint-aware type (e.g., `TaintedGlobal`,
    `TaintedStructMember`, or `TaintedVarOffset`), it is returned as-is.

    Args:
        mlil_loc (MediumLevelILInstruction | int): The MLIL instruction or address where the variable
            is first identified during analysis.
        variable (Union[TaintedVar, Variable, TaintedStructMember, TaintedVarOffset]):
            The variable to initialize for taint tracking.

    Returns:
        list: A list containing a single taint-aware variable object (e.g., `TaintedVar`,
        `TaintedGlobal`, etc.), ready for inclusion in the taint propagation queue.

    Raises:
        ValueError: If the input `variable` is of an unsupported type.
    """
    if isinstance(variable, TaintedVar) or isinstance(variable, Variable):
        if isinstance(mlil_loc, int):
            return [TaintedVar(variable, TaintConfidence.Tainted, mlil_loc)]

        else:
            return [TaintedVar(variable, TaintConfidence.Tainted, mlil_loc.address)]

    elif isinstance(variable, (TaintedGlobal, TaintedVarOffset, TaintedStructMember)):
        return [variable]

    else:
        raise ValueError(
            f"[{Fore.RED}ERROR{Fore.RESET}] Could not find variable with that name.",
            variable,
            type(variable),
        )


def get_var_name(
    v: Union[TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar]
) -> str:
    """
    Retrieves a consistent, human-readable name for a tainted variable or related object.

    This function abstracts the logic needed to extract the appropriate identifier for different
    taint-aware variable types (e.g., global, struct member, offset-based). It is commonly used
    to normalize variable names for comparison, hashing, or display purposes.

    Args:
        v (Union[TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar]):
            A taint-wrapped variable object from the analysis framework.

    Returns:
        str: The variable name as a string.

    Notes:
        - For TaintedGlobal: returns the global variable name.
        - For TaintedStructMember: returns the struct member name as a string.
        - For TaintedVarOffset: returns the `.name` attribute directly.
        - For TaintedVar: returns `.variable.name`.
    """
    if isinstance(v, TaintedGlobal):
        return v.variable

    elif isinstance(v, TaintedStructMember):
        return str(v.member)

    elif isinstance(v, TaintedVarOffset):
        return v.name

    else:
        return v.variable.name


def extract_var_use_sites(
    var_to_trace: Union[
        TaintedGlobal, TaintedStructMember, TaintedVar, TaintedVarOffset
    ],
    function_object: Function,
    analysis,
) -> list:
    """
    Extracts all MLIL use sites for a given variable within a function.

    Depending on the type of `var_to_trace`, this function locates all instructions
    in the specified function that reference or interact with the variable:

    - For `TaintedGlobal`, it finds global references by matching constant pointers.
    - For `TaintedStructMember`, it locates struct field accesses with matching offsets.
    - For other variables (e.g., `TaintedVar`, `TaintedVarOffset`), it uses Binary Ninja's
      built-in MLIL variable reference retrieval.

    Args:
        var_to_trace (Union[TaintedGlobal, TaintedStructMember, TaintedVar, TaintedVarOffset]):
            The tainted variable object to analyze for use sites.
        function_object (Function): The Binary Ninja function in which to search for use.
        analysis (Analysis): The analysis context providing helpers and binary view access.

    Returns:
        list: A list of `MediumLevelILInstruction` objects where the variable is used.
    """
    if isinstance(var_to_trace, TaintedGlobal):
        return get_mlil_glob_refs(analysis, function_object, var_to_trace)

    elif isinstance(var_to_trace, TaintedStructMember):
        return get_struct_field_refs(analysis.bv, var_to_trace)

    else:
        return function_object.get_mlil_var_refs(var_to_trace.variable)


def skip_instruction(
    mlil_loc: MediumLevelILInstruction,
    first_mlil_loc: MediumLevelILInstruction,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    trace_type: SliceType,
    analysis,
    function_object: Function,
) -> Union[bool, bool]:
    """
    Determines whether a given MLIL instruction should be skipped during taint tracing.

    This function prevents incorrect or redundant propagation by skipping instructions
    based on control flow order, dereference/offset mismatch, or trace context.

    Args:
        mlil_loc (MediumLevelILInstruction): The instruction currently being evaluated for tracing.
        first_mlil_loc (MediumLevelILInstruction): The original instruction that initiated the slice.
        var_to_trace (Union[TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset]):
            The variable or field being traced.
        trace_type (SliceType): Direction of the slice (SliceType.Forward or SliceType.Backward).
        analysis: The taint analysis context or engine instance.
        function_object (Function): The function in which this instruction resides.

    Returns:
        Tuple[bool, bool]:
            - First value (`skip_loc`): True if the instruction should be skipped and not processed.
            - Second value (`process_var`): True if the variable should still be processed, even if the instruction is skipped.
    """
    if first_mlil_loc.address == var_to_trace.loc_address:
        if get_connected_var(analysis, function_object, var_to_trace):
            return False, True

    if not mlil_loc:
        return True, False

    if trace_type == SliceType.Forward:
        if mlil_loc.instr_index < first_mlil_loc.instr_index and var_to_trace.variable not in mlil_loc.vars_read:
            return True, False

    elif trace_type == SliceType.Backward and var_to_trace.variable not in mlil_loc.vars_read:
        if mlil_loc.instr_index > first_mlil_loc.instr_index:
            return True, False

    if isinstance(var_to_trace, TaintedVarOffset):
        if not is_address_of_field_offset_match(mlil_loc, var_to_trace):
            return True, False

    return False, True


def append_tainted_loc(
    function_object: Function,
    collected_locs: List[TaintedLOC],
    mlil_loc: MediumLevelILInstruction,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    analysis,
) -> None:
    """
    Append a tainted program location to the list of collected locations.

    Constructs a `TaintedLOC` object from the given MLIL instruction and traced variable,
    resolves its connected variable, and stores the taint information.

    Args:
        function_object (Function): The function containing the instruction.
        collected_locs (List[TaintedLOC]): The running list of collected taint locations.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction to associate with the taint.
        var_to_trace (Union[TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset]):
            The variable being traced for taint.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
    """
    collected_locs.append(
        TaintedLOC(
            mlil_loc,
            mlil_loc.address,
            var_to_trace,
            get_connected_var(
                analysis=analysis,
                function_object=function_object,
                target_variable=var_to_trace,
            ),
            var_to_trace.confidence_level,
            function_object=function_object,
        )
    )


def append_tainted_var_by_type(
    tainted_var: Union[MediumLevelILVar, MediumLevelILConstPtr],
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    vars_found: list,
    mlil_loc: MediumLevelILInstruction,
    analysis,
) -> None:
    """
    Appends the correct taint wrapper (TaintedVar or TaintedGlobal) to the variable worklist.

    Determines whether the input MLIL variable is a constant pointer (i.e. global) or
    a local variable, and appends the corresponding BinGoggles taint object to `vars_found`.

    Args:
        tainted_var: The MLIL variable or constant pointer found in the instruction.
        var_to_trace: The original tainted variable being traced.
        vars_found: The worklist of tainted variables to be analyzed.
        mlil_loc: The MLIL instruction address where the variable was found.
        analysis: The main analysis object providing symbol, taint utilities and binary view.
    """

    if isinstance(tainted_var, MediumLevelILVar) or isinstance(tainted_var, Variable):
        var_object = tainted_var.var if hasattr(tainted_var, "var") else tainted_var
        if var_object != var_to_trace.variable:
            vars_found.append(
                TaintedVar(
                    tainted_var.var if hasattr(tainted_var, "var") else tainted_var,
                    TaintConfidence.Tainted,
                    mlil_loc.address,
                )
            )

    else:
        glob_symbol = get_symbol_from_const_ptr(analysis.bv, tainted_var)
        if glob_symbol:
            vars_found.append(
                TaintedGlobal(
                    glob_symbol.name,
                    var_to_trace.confidence_level,
                    mlil_loc.address,
                    tainted_var,
                    glob_symbol,
                )
            )


def propagate_mlil_store_struct(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    collected_locs: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    vars_found: list,
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
) -> None:
    """
    Handles propagation for struct-related MLIL_STORE_STRUCT and MLIL_SET_VAR operations.

    Extracts and appends `TaintedStructMember` variables when a field in a struct is
    assigned or loaded, and appends the corresponding `TaintedLOC` to the trace.

    Args:
        function_object: The Binary Ninja function context.
        mlil_loc: The MLIL instruction performing the store or assignment.
        collected_locs: List to track visited tainted locations.
        var_to_trace: The current tainted variable being traced.
        vars_found: Worklist of tainted variables to continue tracing.
        analysis: The main analysis object providing symbol, taint utilities and binary view
        trace_type: Direction of slicing (forward or backward).
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    skip_loc, process_var = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_object,
    )
    if not skip_loc:
        append_tainted_loc(
            function_object, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if process_var:
        struct_offset = mlil_loc.ssa_form.offset
        instr_hlil = function_object.get_llil_at(mlil_loc.address).hlil

        if instr_hlil.operation == int(HighLevelILOperation.HLIL_ASSIGN):
            lhs = instr_hlil.dest

            if lhs.operation == int(HighLevelILOperation.HLIL_DEREF_FIELD):
                struct_offset = lhs.offset
                base_expr = lhs.src

                if base_expr.operation == int(HighLevelILOperation.HLIL_VAR):
                    base_var = base_expr.var
                    tainted_struct_member = TaintedStructMember(
                        loc_address=instr_hlil.address,
                        member=get_struct_field_name(mlil_loc),
                        offset=struct_offset,
                        hlil_var=base_var,
                        variable=mlil_loc.dest.var,
                        confidence_level=TaintConfidence.Tainted,
                    )

                    vars_found.append(tainted_struct_member)

        elif mlil_loc.operation == int(MediumLevelILOperation.MLIL_SET_VAR):
            struct_offset = mlil_loc.ssa_form.src.offset
            source = mlil_loc.src
            source_hlil = instr_hlil.src

            if source.operation == int(MediumLevelILOperation.MLIL_LOAD_STRUCT):
                base_var = source_hlil.var
                tainted_struct_member = TaintedStructMember(
                    loc_address=mlil_loc.address,
                    member=get_struct_field_name(mlil_loc),
                    offset=struct_offset,
                    hlil_var=base_var,
                    variable=mlil_loc.src.src.var,
                    confidence_level=TaintConfidence.Tainted,
                )

                vars_found.append(tainted_struct_member)


def propagate_mlil_store(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    collected_locs: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    vars_found: list,
    already_iterated: list,
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
) -> None:
    """
    Handle taint propagation for MLIL_STORE operations.

    This function analyzes a `MLIL_STORE` instruction to extract the base address and potential
    offset (if present), and determines whether the accessed memory location is influenced by a
    previously tainted variable or a global. It appends newly discovered tainted variables
    (as `TaintedVarOffset`) to the taint tracking list and records the instruction location.

    Args:
        function_object (Function): The function containing the MLIL instruction.
        mlil_loc (MediumLevelILInstruction): The store instruction being analyzed.
        collected_locs (list): List of `TaintedLOC` objects visited during this trace.
        var_to_trace (Union[TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset]):
            The variable from which taint is being propagated.
        vars_found (list): A list that will be updated with newly discovered tainted variables.
        already_iterated (list): A list of previously visited variables, used to determine taint propagation.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    skip_loc, process_var = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_object,
    )
    if not skip_loc:
        append_tainted_loc(
            function_object, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if process_var:
        address_variable, offset_variable = None, None
        offset_var_taintedvar = None
        addr_var = None
        offset = None

        if len(mlil_loc.dest.operands) == 1:
            addr_var = mlil_loc.dest.operands[0]

        elif len(mlil_loc.dest.operands) == 2:
            address_variable, offset_variable = mlil_loc.dest.operands
            if isinstance(offset_variable, MediumLevelILConst):
                addr_var, offset = mlil_loc.dest.operands
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
                TaintedVarOffset(
                    variable=(
                        addr_var if isinstance(addr_var, Variable) else addr_var.var
                    ),
                    offset=offset,
                    offset_var=offset_var_taintedvar,
                    confidence_level=TaintConfidence.Tainted,
                    loc_address=mlil_loc.address,
                    targ_function=function_object,
                )
            )

        elif offset_variable:
            vars_found.append(
                TaintedVarOffset(
                    variable=address_variable,
                    offset=offset,
                    offset_var=TaintedVar(
                        variable=offset_variable,
                        confidence_level=TaintConfidence.NotTainted,
                        loc_address=mlil_loc.address,
                    ),
                    confidence_level=var_to_trace.confidence_level,
                    loc_address=mlil_loc.address,
                    targ_function=function_object,
                )
            )
            if isinstance(offset_variable, MediumLevelILConstPtr):
                glob_symbol = get_symbol_from_const_ptr(analysis.bv, offset_variable)

                if glob_symbol:
                    vars_found.append(
                        TaintedVarOffset(
                            variable=address_variable,
                            offset=offset,
                            offset_var=TaintedGlobal(
                                glob_symbol.name,
                                TaintConfidence.NotTainted,
                                mlil_loc.address,
                                offset_variable,
                                glob_symbol,
                            ),
                            confidence_level=var_to_trace.confidence_level,
                            loc_address=mlil_loc.address,
                            targ_function=function_object,
                        )
                    )

        else:
            vars_found.append(
                TaintedVarOffset(
                    variable=(
                        addr_var if isinstance(addr_var, Variable) else addr_var.var
                    ),
                    offset=offset,
                    offset_var=None,
                    confidence_level=TaintConfidence.Tainted,
                    loc_address=mlil_loc.address,
                    targ_function=function_object,
                )
            )


def analyze_function_model(
    mlil_loc: MediumLevelILInstruction,
    func_analyzed: InterprocTaintResult,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    already_iterated: list,
    vars_found: list,
    analysis,
) -> None:
    """
    Applies a modeled function's taint propagation rules to a call instruction.

    This function uses an `InterprocTaintResult` from a pre-modeled or previously analyzed
    function to propagate taint based on argument relationships and return value behavior.

    Supports both fixed-parameter and vararg models:
    - For vararg models: propagates taint if the traced variable appears in a vararg position.
    - For fixed models: propagates taint based on index mapping of taint sources to destinations.
    - If the return value is tainted, it is added to the taint worklist.

    Args:
        mlil_loc: The MLIL call instruction being modeled.
        func_analyzed: The result of taint analysis for the modeled function.
        var_to_trace: The current tainted variable being traced into the model.
        already_iterated: List of previously traced tainted variables (to avoid duplication).
        vars_found: Worklist queue to which new tainted variables are added.
        analysis: The main analysis object providing symbol, taint utilities and binary view.
    """
    # Handle vararg function calls
    if func_analyzed.taints_varargs:
        tainted_variables_to_add = set()

        try:
            dest_tainted = [
                i.var if hasattr(i, "var") else None for i in mlil_loc.params
            ].index(var_to_trace.variable) > func_analyzed.vararg_start_index
        except ValueError:
            dest_tainted = None

        if dest_tainted:
            vararg_indexes = [
                getattr(i, "var", None)
                for i in mlil_loc.params[func_analyzed.vararg_start_index :]
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
                    for t_dst_indx in func_analyzed.taint_destinations:
                        tainted_variables_to_add.add(mlil_loc.params[t_dst_indx])

        for t_var in tainted_variables_to_add:
            append_tainted_var_by_type(
                t_var, var_to_trace, vars_found, mlil_loc, analysis
            )

        if func_analyzed.taints_return:
            for t_var in mlil_loc.vars_written:
                append_tainted_var_by_type(
                    t_var, var_to_trace, vars_found, mlil_loc, analysis
                )

    # Handle non-vararg function calls
    else:
        for t_src_indx in func_analyzed.taint_sources:
            for t_dst_indx in func_analyzed.taint_destinations:
                append_tainted_var_by_type(
                    mlil_loc.params[t_dst_indx],
                    var_to_trace,
                    vars_found,
                    mlil_loc,
                    analysis,
                )

        if func_analyzed.taints_return:
            for t_var in mlil_loc.vars_written:
                append_tainted_var_by_type(
                    t_var, var_to_trace, vars_found, mlil_loc, analysis
                )


def analyze_new_imported_function(
    mlil_loc: MediumLevelILInstruction,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    vars_found: list,
    analysis,
):
    """
    Analyze taint propagation through a call to an imported or otherwise unresolved function.

    This function attempts to trace the effects of taint when a call is made to a new or imported function
    that is not part of the core binary. It uses interprocedural taint tracing to detect whether:
      - The return value is tainted
      - Any parameters passed to the function propagate taint back

    If taint is found, appropriate `TaintedVar` or `TaintedVarOffset` instances are created and added to
    the `vars_found` list.

    Args:
        mlil_loc (MediumLevelILInstruction): The MLIL instruction for the function call.
        var_to_trace (Union[TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset]):
            The original variable being traced for taint.
        vars_found (list): List of new tainted variables discovered via interprocedural analysis.
        analysis (Analysis): The main `Analysis` object handling taint propagation and resolution.
    """
    _, tainted_func_param = get_func_param_from_call_param(
        analysis.bv, mlil_loc, var_to_trace
    )

    call_func_object = addr_to_func(analysis.bv, int(str(mlil_loc.dest), 16))

    if call_func_object:
        interproc_results = analysis.trace_function_taint(
            function_node=call_func_object,
            tainted_params=tainted_func_param,
            binary_view=analysis.bv,
        )

        if analysis.verbose:
            analysis.trace_function_taint_printed = False

        if interproc_results.is_return_tainted and mlil_loc.vars_written:
            for var_assigned in mlil_loc.vars_written:
                append_tainted_var_by_type(
                    var_assigned, var_to_trace, vars_found, mlil_loc, analysis
                )

        if interproc_results.tainted_param_names:
            zipped_results = list(
                zip(
                    interproc_results.tainted_param_names,
                    mlil_loc.params,
                )
            )

            for _, var in zipped_results:
                append_tainted_var_by_type(
                    var, var_to_trace, vars_found, mlil_loc, analysis
                )


def propagate_mlil_call(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    collected_locs: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    vars_found: list,
    already_iterated: list,
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
) -> None:
    """
    Handles taint propagation for MLIL function call instructions.

    This function determines if a function call is imported or modeled, analyzes whether its
    parameters or return values are tainted, and adds any resulting tainted variables to the
    propagation worklist. It handles both known function models and previously unseen imported
    functions.

    Args:
        function_object (Function): The Binary Ninja function containing the call.
        mlil_loc (MediumLevelILInstruction): The MLIL call instruction being analyzed.
        collected_locs (list): List of previously recorded tainted locations.
        var_to_trace: The original tainted variable being traced.
        vars_found (list): The queue of tainted variables pending further analysis.
        already_iterated (list): Set of already processed tainted variables (to prevent loops).
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    skip_loc, process_var = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_object,
    )
    if not skip_loc:
        append_tainted_loc(
            function_object, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if process_var:
        if mlil_loc.params:
            imported_function = analysis.resolve_function_type(mlil_loc)
            normalized_function_name = get_modeled_function_name_at_callsite(function_object, mlil_loc)
            if imported_function or normalized_function_name:
                func_analyzed = None
                if imported_function:
                    func_analyzed = analysis.analyze_function_taint(
                        imported_function, var_to_trace
                    )

                elif normalized_function_name:
                    func_analyzed = analysis.analyze_function_taint(
                        imported_function, var_to_trace
                    )


                if func_analyzed and isinstance(func_analyzed, FunctionModel):
                    # If it's a known modeled function, use the model logic
                    analyze_function_model(
                        mlil_loc,
                        func_analyzed,
                        var_to_trace,
                        already_iterated,
                        vars_found,
                        analysis,
                    )

                elif func_analyzed and isinstance(func_analyzed, InterprocTaintResult):
                    # If it's a real function we analyzed, zip tainted params with call params
                    zipped_results = list(
                        zip(
                            func_analyzed.tainted_param_names,
                            mlil_loc.params,
                        )
                    )

                    for _, var in zipped_results:
                        # Wrap each tainted parameter into the appropriate BinGoggles taint type
                        append_tainted_var_by_type(
                            var, var_to_trace, vars_found, mlil_loc, analysis
                        )

                    if func_analyzed.is_return_tainted:
                        # If return value is tainted, treat it as a new tainted variable
                        append_tainted_var_by_type(
                            var, var_to_trace, vars_found, mlil_loc, analysis
                        )

            else:
                # If the function isn't modeled or previously seen, analyze it as a new import
                analyze_new_imported_function(
                    mlil_loc, var_to_trace, vars_found, analysis
                )


def add_read_var(
    mlil_loc: MediumLevelILInstruction,
) -> bool:
    """
    Determine whether the source operand of the given MLIL instruction is a variable reference.

    This function checks if the `.src` operand of a MediumLevelILInstruction is either a `MediumLevelILVar`
    (i.e., a direct variable access) or a `MediumLevelILAddressOf` (i.e., a reference to the address of a variable).

    Args:
        mlil_loc (MediumLevelILInstruction): The MLIL instruction to inspect.

    Returns:
        bool: True if the instruction's source is a variable or a variable address reference; False otherwise.
    """
    if isinstance(mlil_loc.src, MediumLevelILVar) or isinstance(
        mlil_loc.src, MediumLevelILAddressOf
    ):
        return True


def propagate_mlil_set_var(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    vars_found: list,
    already_iterated: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    collected_locs: List[TaintedLOC],
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
) -> None:
    """
    Handles taint propagation for MLIL_SET_VAR instructions, including memory loads with offset tracking.

    This function traces variable assignments and propagates taint to destination variables.
    Special handling is included for `MLIL_LOAD` operations with address and offset variables,
    which are wrapped as `TaintedVarOffset` if taint propagation applies.

    Args:
        function_object (Function): The Binary Ninja function containing the instruction.
        mlil_loc (MediumLevelILInstruction): The MLIL_SET_VAR instruction to analyze.
        vars_found (list): Worklist queue to which new tainted variables are added.
        already_iterated (list): List of previously traced tainted variables (for recursion guard).
        var_to_trace: The current tainted variable being traced.
        collected_locs (List[TaintedLOC]): List of tainted locations recorded so far.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    skip_loc, process_var = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_object,
    )
    if not skip_loc:
        append_tainted_loc(
            function_object, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if process_var:
        if isinstance(mlil_loc.src, MediumLevelILLoad) or isinstance(
            mlil_loc.dest, MediumLevelILLoad
        ):
            if isinstance(mlil_loc.src, MediumLevelILLoad):
                try:
                    address_variable, offset_variable = mlil_loc.src.vars_read

                except ValueError:
                    address_variable = mlil_loc.src.vars_read[0]
                    offset_variable = None

                except Exception as e:
                    print(
                        "[LOC (unhandled)]: ",
                        mlil_loc,
                        hex(mlil_loc.address),
                    )
                    print("[Error]: ", e)

            else:
                address_variable, offset_variable = mlil_loc.dest.vars_written

            offset_var_taintedvar = [
                var.variable
                for var in already_iterated
                if var.variable == offset_variable
            ]

            if offset_var_taintedvar:
                vars_found.append(
                    TaintedVarOffset(
                        variable=address_variable,
                        offset=None,
                        offset_var=offset_var_taintedvar[0],
                        confidence_level=var_to_trace.confidence_level,
                        loc_address=mlil_loc.address,
                        targ_function=function_object,
                    )
                )
                if (
                    offset_var_taintedvar[0].confidence_level == TaintConfidence.Tainted
                    and var_to_trace.confidence_level == TaintConfidence.Tainted
                    or var_to_trace.confidence_level == TaintConfidence.MaybeTainted
                ):
                    if mlil_loc.vars_written:
                        for variable_written_to in mlil_loc.vars_written:
                            append_tainted_var_by_type(
                                variable_written_to,
                                var_to_trace,
                                vars_found,
                                mlil_loc,
                                analysis,
                            )
                else:
                    if mlil_loc.vars_written:
                        for variable_written_to in mlil_loc.vars_written:
                            append_tainted_var_by_type(
                                variable_written_to,
                                var_to_trace,
                                vars_found,
                                mlil_loc,
                                analysis,
                            )

            else:
                for variable_written_to in mlil_loc.vars_written:
                    append_tainted_var_by_type(
                        variable_written_to,
                        var_to_trace,
                        vars_found,
                        mlil_loc,
                        analysis,
                    )

        elif mlil_loc.vars_written:
            for variable_written_to in mlil_loc.vars_written:
                append_tainted_var_by_type(
                    variable_written_to, var_to_trace, vars_found, mlil_loc, analysis
                )

        if mlil_loc.vars_read:
            for variable_written_to in mlil_loc.vars_read:
                if add_read_var(mlil_loc):
                    append_tainted_var_by_type(
                        variable_written_to,
                        var_to_trace,
                        vars_found,
                        mlil_loc,
                        analysis,
                    )


def propagate_mlil_set_var_field(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    vars_found: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    collected_locs: List[TaintedLOC],
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
):
    """
    Handles taint propagation for MLIL_SET_VAR_FIELD instructions.

    When a struct field is written to this function propagates
    taint into the destination variable and records the instruction as a tainted location.

    Args:
        function_object (Function): The Binary Ninja function containing the instruction.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction performing the field assignment.
        vars_found (list): Queue of tainted variables to be analyzed.
        var_to_trace: The original tainted variable being traced.
        collected_locs (List[TaintedLOC]): Accumulated list of tainted instruction locations.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    skip_loc, process_var = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_object,
    )
    if not skip_loc:
        append_tainted_loc(
            function_object, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if process_var:
        append_tainted_var_by_type(
            mlil_loc.dest, var_to_trace, vars_found, mlil_loc, analysis
        )


def propagate_mlil_unhandled_operation(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    vars_found: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    collected_locs: List[TaintedLOC],
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
) -> None:
    """
    Handles taint propagation for MLIL instructions not explicitly modeled elsewhere.

    If the instruction performs a recognized read-write operation and writes to variables,
    this function propagates taint to the written variables. It also logs the instruction
    as a tainted location.

    Args:
        function_object (Function): The Binary Ninja function containing the instruction.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction to analyze.
        vars_found (list): Worklist queue to which new tainted variables are added.
        var_to_trace: The current tainted variable being traced.
        collected_locs (List[TaintedLOC]): List of tainted locations recorded so far.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    skip_loc, process_var = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_object,
    )
    if not skip_loc:
        append_tainted_loc(
            function_object, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if process_var:
        if mlil_loc.vars_written and is_rw_operation(mlil_loc):
            for variable_written_to in mlil_loc.vars_written:
                append_tainted_var_by_type(
                    variable_written_to, var_to_trace, vars_found, mlil_loc, analysis
                )


def sort_collected_locs(
    trace_type: SliceType, collected_locs: list, already_iterated: list
) -> None:
    """
    Sorts and deduplicates collected tainted locations based on the direction of the trace.

    This function organizes the list of collected `TaintedLOC` objects in either forward or
    backward instruction order. It also removes duplicate entries based on their address.

    Args:
        trace_type (SliceType): Direction of taint tracing (Forward or Backward).
        collected_locs (list): List of `TaintedLOC` objects gathered during taint analysis.
        already_iterated (list): List of tainted variables already processed.

    Returns:
        tuple:
            - sorted_locs (list): Ordered and deduplicated list of tainted locations.
            - already_iterated (list): List of already processed variables.
    """
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


def propagate_by_mlil_operation(
    function_object: Function,
    mlil_loc: MediumLevelILInstruction,
    vars_found: list,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ],
    collected_locs: List[TaintedLOC],
    already_iterated: list,
    analysis,
    trace_type: SliceType,
    first_mlil_loc: MediumLevelILInstruction,
) -> None:
    """
    Dispatches taint propagation logic based on the MLIL operation type.

    This function routes the current instruction (`mlil_loc`) to the appropriate
    taint propagation handler depending on its operation type, such as STORE,
    CALL, or SET_VAR. Each handler updates the taint state accordingly by appending
    new tainted variables and recording the tainted instruction.

    Args:
        function_object (Function): The Binary Ninja function containing the instruction.
        mlil_loc (MediumLevelILInstruction): The instruction to process.
        vars_found (list): Worklist queue for tainted variables pending analysis.
        var_to_trace: The variable currently being traced through the program.
        collected_locs (List[TaintedLOC]): Accumulated list of tainted instruction locations.
        already_iterated (list): Variables already seen in the trace (loop prevention).
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    match int(mlil_loc.operation):
        case int(MediumLevelILOperation.MLIL_STORE_STRUCT):
            propagate_mlil_store_struct(
                function_object,
                mlil_loc,
                collected_locs,
                var_to_trace,
                vars_found,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case int(MediumLevelILOperation.MLIL_STORE):
            propagate_mlil_store(
                function_object,
                mlil_loc,
                collected_locs,
                var_to_trace,
                vars_found,
                already_iterated,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case int(MediumLevelILOperation.MLIL_CALL):
            propagate_mlil_call(
                function_object,
                mlil_loc,
                collected_locs,
                var_to_trace,
                vars_found,
                already_iterated,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case int(MediumLevelILOperation.MLIL_SET_VAR):
            propagate_mlil_set_var(
                function_object,
                mlil_loc,
                vars_found,
                already_iterated,
                var_to_trace,
                collected_locs,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case int(MediumLevelILOperation.MLIL_SET_VAR_FIELD):
            propagate_mlil_set_var_field(
                function_object,
                mlil_loc,
                vars_found,
                var_to_trace,
                collected_locs,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case _:
            propagate_mlil_unhandled_operation(
                function_object,
                mlil_loc,
                vars_found,
                var_to_trace,
                collected_locs,
                analysis,
                trace_type,
                first_mlil_loc,
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
                2. List of TaintedVar (or other bingoggles tainted variable like objects) objects that were traced during the analysis.
            - Returns None if the trace cannot be performed (e.g., variable not found or invalid trace type).
    """
    collected_locs = []
    already_iterated = []

    vars_found = init_vars_found(mlil_loc, variable)

    while vars_found:
        var_to_trace = vars_found.pop(0)
        var_name = get_var_name(var_to_trace)

        # never trace the same variable twice
        if var_name in [get_var_name(var) for var in already_iterated]:
            continue

        # since we are tracing a new variable, we're going to append to the already_iterated list
        already_iterated.append(var_to_trace)

        # extract use sites from var_to_trace
        variable_use_sites = extract_var_use_sites(
            var_to_trace, function_object, analysis
        )

        for ref in variable_use_sites:
            instr_mlil = function_object.get_llil_at(ref.address).mlil
            # Determine if we should skip this instruction
            skip_loc, process_var = skip_instruction(
                mlil_loc,
                mlil_loc,
                var_to_trace,
                trace_type,
                analysis,
                function_object,
            )

            if not skip_loc and process_var:
                # Collect variables for `vars_found` list and `collected_locs` list based off of the instr_mlil operation
                propagate_by_mlil_operation(
                    function_object,
                    instr_mlil,
                    vars_found,
                    var_to_trace,
                    collected_locs,
                    already_iterated,
                    analysis,
                    trace_type,
                    mlil_loc,
                )

    return sort_collected_locs(trace_type, collected_locs, already_iterated)


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
    """
    Converts a variable name or MediumLevelILVar into a Binary Ninja Variable object.

    Searches the function's variable list for a match by name. If a MediumLevelILVar is passed,
    its `.name` is extracted and used for matching.

    Args:
        var_as_str (str | MediumLevelILVar): The variable name or MLIL variable to resolve.
        function_object (Function): The Binary Ninja function containing the variable.

    Returns:
        Variable | None: The matching Variable object, or None if not found.
    """
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
