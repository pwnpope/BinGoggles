from binaryninja.variable import Variable
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    MediumLevelILAddressOfField,
    MediumLevelILLoad,
    MediumLevelILConstPtr,
    MediumLevelILVar,
    MediumLevelILConst,
    MediumLevelILAddressOf,
    MediumLevelILVarSsa,
)
from binaryninja.highlevelil import HighLevelILOperation, HighLevelILInstruction
from colorama import Fore
from typing import Sequence, Dict, Tuple, Optional, Union
from .bingoggles_types import *
from binaryninja.enums import MediumLevelILOperation, SymbolType
from binaryninja import BinaryView, Symbol, types
from functools import cache
from .function_registry import get_modeled_function_name_at_callsite, get_function_model


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
def resolve_modeled_variadic_function(
    function_node: Function,
    mlil_loc: MediumLevelILInstruction,
) -> Optional[FunctionModel]:
    """
    Determines if a called function should have its variadic arguments patched
    based on a predefined function model. This function is intended to be called when processing an MLIL call instruction.

    Args:
        function_node (binaryninja.Function): The Binary Ninja Function object
            that contains the `mlil_loc` (the calling function).
        mlil_loc (binaryninja.MediumLevelILInstruction): The MLIL call instruction
            that is being analyzed. This instruction's destination (`mlil_loc.dest.value.value`)
            should point to the start address of the called function.
        call_name (str): The name of the called function (e.g., "printf", "_IO_printf").

    Returns:
        Union[FunctionModel, None]: The `FunctionModel` object for the called function
            if it's determined that its variadic arguments need to be applied/patched
            in Binary Ninja's analysis. Returns `None` otherwise.
    """
    function_call_address = mlil_loc.dest.value.value
    call_func_object = function_node.view.get_function_at(function_call_address)
    if hasattr(call_func_object, "name"):
        call_name = call_func_object.name
        function_model = get_function_model(call_name)

        if function_model and function_model.vararg_start_index:
            varg_start_index = function_model.vararg_start_index
            if (
                len(list(call_func_object.parameter_vars)) > varg_start_index
                and not call_func_object.has_variable_arguments
            ):
                return function_model

    return None


def patch_function_params(
    function_node: Function,
    mlil_loc: MediumLevelILInstruction,
    function_model: FunctionModel,
) -> None:
    """
    Applies a programmatically determined variadic type to a Binary Ninja function.

    Args:
        function_node (binaryninja.Function): The Binary Ninja Function object
            representing the function that contains the MLIL call instruction.
        mlil_loc (binaryninja.MediumLevelILInstruction): The MLIL call instruction
            whose destination points to the function being patched.
        function_model (FunctionModel): A custom model object that provides
            information about the called function.
    """
    function_call_address = mlil_loc.dest.value.value
    call_func_object = function_node.view.get_function_at(function_call_address)
    varg_start_index = function_model.vararg_start_index

    new_params = list(call_func_object.type.parameters)[:varg_start_index]
    return_type = call_func_object.type.return_value
    calling_convention = call_func_object.calling_convention
    if calling_convention is None:
        calling_convention = call_func_object.arch.default_calling_convention

    new_func_type = types.FunctionBuilder.create(
        return_type=return_type,
        calling_convention=calling_convention,
        params=new_params,
        var_args=True,
    )

    call_func_object.set_user_type(new_func_type)


"""
Since we'll be making changes it should ask the user if they want to save the changes to a new BNDB
ask user -> ask for new file name -> save

we can do this by having a variable in the analysis object and then if 
we run the `patch_function_params` function than we can set that variable to true
"""


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
        MediumLevelILOperation.MLIL_LOAD_STRUCT.value,
        MediumLevelILOperation.MLIL_VAR_FIELD.value,
        MediumLevelILOperation.MLIL_STORE_STRUCT.value,
    ]

    for block in func_object.mlil:
        for instr_mlil in block:
            if (
                instr_mlil.operation in struct_ops
                or hasattr(instr_mlil, "src")
                and hasattr(instr_mlil.src, "operation")
                and instr_mlil.src.operation in struct_ops
            ):
                if (
                    instr_mlil.operation
                    == MediumLevelILOperation.MLIL_STORE_STRUCT.value
                ):
                    if instr_mlil.offset == tainted_struct_member.offset:
                        mlil_use_sites.add(instr_mlil)

                elif (
                    instr_mlil.src.operation
                    == MediumLevelILOperation.MLIL_LOAD_STRUCT.value
                ):
                    if instr_mlil.src.offset == tainted_struct_member.offset:
                        mlil_use_sites.add(instr_mlil)

                elif (
                    instr_mlil.src.operation
                    == MediumLevelILOperation.MLIL_VAR_FIELD.value
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


def addr_to_func(bv: BinaryView, address: int) -> Optional[Function]:
    """
    `addr_to_func` Get the function object from an address

    Args:
        bv: (BinaryView): Binary Ninja BinaryView
        address (int): address to the start or within the function object

    Returns:
        Binary ninja function object
    """
    function_node = bv.get_functions_containing(address)
    if function_node:
        return function_node[0]

    else:
        return None


def func_name_to_object(bv: BinaryView, func_name: str) -> Optional[None]:
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
    if loc.operation == MediumLevelILOperation.MLIL_SET_VAR.value:
        return loc.tokens[-1].text

    elif loc.operation == MediumLevelILOperation.MLIL_STORE_STRUCT.value:
        field_name_index = next(
            (i for i, t in enumerate(loc.tokens) if t.text == " = "), None
        )
        return loc.tokens[field_name_index - 1].text

    raise ValueError(f"[Error] Could not find struct member name in LOC: {loc}")


@cache
def get_mlil_glob_refs(
    analysis, function_node: Function, var_to_trace: TaintedGlobal
) -> List:
    """
    Finds all MLIL instructions that reference a given global variable.

    This function identifies and collects use sites of a `TaintedGlobal` object by scanning
    all MLIL instructions in the specified function. It ensures accurate matches by validating
    symbol references and filtering false positives.

    Args:
        analysis (Analysis): The analysis context containing the Binary Ninja BinaryView.
        function_node (Function): The function in which to search for global variable references.
        var_to_trace (TaintedGlobal): The global variable to track in the function.

    Returns:
        list: A list of MLIL instructions that reference `var_to_trace`.
    """
    variable_use_sites = []
    if var_to_trace.variable in analysis.glob_refs_memoized.keys():
        return analysis.glob_refs_memoized[var_to_trace.variable]

    for instr_mlil in function_node.mlil.instructions:
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
        MediumLevelILOperation.MLIL_SET_VAR.value,
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED.value,
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD.value,
        MediumLevelILOperation.MLIL_SET_VAR_FIELD.value,
        MediumLevelILOperation.MLIL_SET_VAR_SPLIT.value,
        MediumLevelILOperation.MLIL_LOAD.value,
        MediumLevelILOperation.MLIL_LOAD_STRUCT.value,
        MediumLevelILOperation.MLIL_STORE.value,
        MediumLevelILOperation.MLIL_STORE_STRUCT.value,
    ]

    def op_is_rw(il):
        return hasattr(il, "operation") and int(il.operation) in read_write_ops

    if not op_is_rw(instr_mlil):
        return False

    return True


def get_section_by_addr(binary_view: BinaryView, address: int) -> Optional[str]:
    """
    Get the section name that contains the given address in the binary.

    Args:
        binary_view (BinaryView): The binary view object, which represents the structure
                                   of the loaded binary, including its sections.
        address (int): The address to check within the binary.

    Returns:
        str: The name of the section that contains the given address, or `None` if the
              address is not found within any section.
    """
    for name, section in binary_view.sections.items():
        if address <= section.end and address >= section.start:
            return name

    return None


@cache
def resolve_got_callsite(binary_view: BinaryView, call_addr: int) -> Optional[Function]:
    """
    Resolve a function call site to its corresponding Global Offset Table (GOT) entry.

    This function identifies the target function for a dynamically linked function call
    made via the GOT. It attempts to resolve the address of the function being called,
    based on the information available in the binary's medium-level intermediate language (MLIL).

    Args:
        binary_view (BinaryView): The binary view object representing the loaded binary.
        call_addr (int): The address of the call site (a function call instruction),
                          typically extracted from the MLIL instruction (`instr_mlil.dest.value.value`).

    Returns:
        Function or None: The function object that corresponds to the resolved GOT entry,
                          or `None` if the function could not be resolved.
    """
    call_object = binary_view.get_function_at(call_addr)
    mlil_blocks = call_object.medium_level_il

    if len(mlil_blocks) < 2:
        for block in mlil_blocks:
            for instr in block:
                if instr.operation == MediumLevelILOperation.MLIL_JUMP.value:
                    entry_address = instr.dest.src.value.value
                    section_name = get_section_by_addr(binary_view, entry_address)
                    section = binary_view.sections.get(section_name)
                    for addr in range(
                        section.start, section.end, binary_view.address_size
                    ):
                        if addr == entry_address:
                            ptr = binary_view.read_pointer(addr)
                            function_resolved = binary_view.get_function_at(ptr)
                            if function_resolved:
                                return function_resolved

                else:
                    return None

    return None


def get_connected_var(
    analysis,
    function_node: Function,
    target_variable: Union[
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
    ],
) -> Optional[Variable]:
    """
    Identifies the most recent source variable that was assigned to the given target variable.

    This function analyzes MLIL instructions within the specified function to locate the
    most recent assignment (typically via `MLIL_SET_VAR`, `MLIL_STORE`, or struct assignment)
    that propagated data into the `target_variable`. This is useful in backward dataflow
    analysis to trace the origin of a variable's value, or in forward slicing to map propagation
    chains.

    Args:
        analysis (Analysis): The analysis engine instance that provides context and utilities.
        function_node (Function): Binary Ninja function object where the variable is located.
        target_variable (TaintedVar | TaintedGlobal | TaintedVarOffset | TaintedStructMember):
            The variable whose source (vars_read) should be located.

    Returns:
        Variable | None:
            - The source variable from which the target variable most recently received its value.
            - None if no such assignment was found or the propagation path cannot be determined.
    """
    connected_candidates = []

    if isinstance(target_variable, (TaintedVar, TaintedVarOffset)):
        refs = extract_var_use_sites(target_variable, function_node, analysis)

        for ref in refs:
            mlil = function_node.get_llil_at(ref.address).mlil
            if not mlil:
                continue

            if (
                mlil.vars_written
                and mlil.vars_written[0] == target_variable.variable
                and mlil.vars_read
            ):
                connected_candidates.append((mlil.address, mlil.vars_read[0]))

    elif isinstance(target_variable, TaintedGlobal):
        refs = get_mlil_glob_refs(analysis, function_node, target_variable)

        for ref in refs:
            mlil = function_node.get_llil_at(ref.address).mlil
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
        refs = get_struct_field_refs(function_node.view, target_variable)

        for ref in refs:
            mlil = function_node.get_llil_at(ref.address).mlil
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
        Union[TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar],
        Variable,
    ],
) -> List:
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
        variable (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ] | Variable):
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
        v Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]:
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
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
    ],
    function_node: Function,
    analysis,
) -> List:
    """
    Extracts all MLIL use sites for a given variable within a function.

    Depending on the type of `var_to_trace`, this function locates all instructions
    in the specified function that reference or interact with the variable:

    - For `TaintedGlobal`, it finds global references by matching constant pointers.
    - For `TaintedStructMember`, it locates struct field accesses with matching offsets.
    - For other variables (e.g., `TaintedVar`, `TaintedVarOffset`), it uses Binary Ninja's
      built-in MLIL variable reference retrieval.

    Args:
        var_to_trace (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]): The tainted variable object to analyze for use sites.
        function_node (Function): The Binary Ninja function in which to search for use.
        analysis (Analysis): The analysis context providing helpers and binary view access.

    Returns:
        list: A list of `MediumLevelILInstruction` objects where the variable is used.
    """
    if isinstance(var_to_trace, TaintedGlobal):
        return get_mlil_glob_refs(analysis, function_node, var_to_trace)

    elif isinstance(var_to_trace, TaintedStructMember):
        return get_struct_field_refs(analysis.bv, var_to_trace)

    else:
        #:TODO add accuracy tracking for TaintedVarOffset
        return function_node.get_mlil_var_refs(
            var_to_trace.variable if hasattr(var_to_trace, "variable") else var_to_trace
        )


@cache
def micro_propagated_slice(
    var_to_trace: Union[
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
    ],
    function_node: Function,
    vars_found: list,
    analysis,
    max_depth=8,
) -> TraceDecision:
    """
    Recursively determines if, when tracing backward from `var_to_trace`, any variables in its propagation chain
    can influence instructions at addresses greater than the current variable's address (i.e., can propagate taint further).
    This function helps avoid false positives in static path analysis by checking if any "parent" variables
    (those that flow into `var_to_trace`) have use sites beyond the current variable's address, and are not already
    present in `vars_found`. The recursion is bounded by `max_depth` to prevent infinite loops.

    Args:
        var_to_trace (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]):
            The variable currently being analyzed for backward propagation.
        function_node (Function): The Binary Ninja function context for the analysis.
        vars_found (list): List of variables already visited in the current trace (to avoid cycles).
        max_depth (int, optional): Maximum recursion depth for the search. Defaults to 5.

    Returns:
        TraceDecision:
            - PROCESS_AND_TRACE if further propagation is possible (i.e., a parent variable can influence later instructions).
            - SKIP_AND_PROCESS otherwise.
    """
    if max_depth == 0:
        return TraceDecision.SKIP_AND_PROCESS

    refs = extract_var_use_sites(var_to_trace, function_node, analysis)
    for ref in refs:
        loc = function_node.get_llil_at(ref.address).mlil
        if hasattr(loc, "vars_read") and loc.vars_read:
            for parent_var in loc.vars_read:
                if any(getattr(v, "variable", None) == parent_var for v in vars_found):
                    continue

                parent_refs = extract_var_use_sites(parent_var, function_node, analysis)
                for parent_ref in parent_refs:
                    if parent_ref.address > getattr(
                        var_to_trace, "addr", getattr(var_to_trace, "loc_address", 0)
                    ):
                        return TraceDecision.PROCESS_AND_TRACE

                if (
                    micro_propagated_slice(
                        parent_var,
                        function_node,
                        tuple(list(vars_found) + [var_to_trace]),
                        analysis,
                        max_depth - 1,
                    )
                    == TraceDecision.PROCESS_AND_TRACE
                ):
                    return TraceDecision.PROCESS_AND_TRACE

    return TraceDecision.SKIP_AND_PROCESS


def is_forward_in_past(
    trace_type: SliceType,
    mlil_loc: MediumLevelILInstruction,
    first_mlil_loc: MediumLevelILInstruction,
):
    """
    Determines if a forward taint trace has encountered an instruction earlier than the starting instruction.

    Args:
        trace_type (SliceType): The direction of the trace (should be SliceType.Forward).
        mlil_loc (MediumLevelILInstruction): The current MLIL instruction being analyzed.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction where the trace began.

    Returns:
        bool: True if tracing forward and the current instruction index is before the starting instruction, False otherwise.
    """
    return (
        trace_type == SliceType.Forward
        and mlil_loc.instr_index < first_mlil_loc.instr_index
    )


def is_backward_in_future(
    trace_type: SliceType,
    mlil_loc: MediumLevelILInstruction,
    first_mlil_loc: MediumLevelILInstruction,
):
    """
    Determines if a backward taint trace has encountered an instruction later than the starting instruction.

    Args:
        trace_type (SliceType): The direction of the trace (should be SliceType.Backward).
        mlil_loc (MediumLevelILInstruction): The current MLIL instruction being analyzed.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction where the trace began.

    Returns:
        bool: True if tracing backward and the current instruction index is after the starting instruction, False otherwise.
    """
    return (
        trace_type == SliceType.Backward
        and mlil_loc.instr_index > first_mlil_loc.instr_index
    )


def skip_instruction(
    mlil_loc: MediumLevelILInstruction,
    first_mlil_loc: MediumLevelILInstruction,
    var_to_trace: Union[
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
    ],
    trace_type: SliceType,
    analysis,
    function_node: Function,
    vars_found,
) -> TraceDecision:
    """
    Determines how to handle an MLIL instruction during taint tracing.

    Args:
        mlil_loc (MediumLevelILInstruction): The current MLIL instruction being analyzed.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction where the trace began.
        var_to_trace (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]):
            The variable currently being traced.
        trace_type (SliceType): The direction of the trace (forward or backward).
        analysis: The analysis context or object.
        function_node (Function): The Binary Ninja function containing the instruction.

    Returns:
        TraceDecision: One of the following actions for the instruction:
            - SKIP_AND_DISCARD: Ignore instruction and variable.
            - SKIP_AND_PROCESS: Skip instruction but allow taint propagation.
            - PROCESS_AND_DISCARD: Process instruction but skip variable.
            - PROCESS_AND_TRACE: Normal tracing.
    """
    if not mlil_loc:
        return TraceDecision.SKIP_AND_DISCARD

    if trace_type == SliceType.Forward:
        micro_decision = micro_propagated_slice(
            var_to_trace, function_node, tuple(vars_found), analysis
        )
        if micro_decision != TraceDecision.PROCESS_AND_TRACE:
            return TraceDecision.SKIP_AND_PROCESS

    if isinstance(var_to_trace, TaintedVarOffset):
        if not is_address_of_field_offset_match(mlil_loc, var_to_trace):
            return TraceDecision.PROCESS_AND_DISCARD

    if first_mlil_loc.address == var_to_trace.loc_address:
        if get_connected_var(analysis, function_node, var_to_trace):
            return TraceDecision.PROCESS_AND_TRACE

    if is_forward_in_past(
        trace_type, mlil_loc, first_mlil_loc
    ) or is_backward_in_future(trace_type, mlil_loc, first_mlil_loc):
        return TraceDecision.SKIP_AND_PROCESS

    return TraceDecision.PROCESS_AND_TRACE


def append_tainted_loc(
    function_node: Function,
    collected_locs: List[TaintedLOC],
    mlil_loc: MediumLevelILInstruction,
    var_to_trace: Union[
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
    ],
    analysis,
) -> None:
    """
    Append a tainted program location to the list of collected locations.

    Constructs a `TaintedLOC` object from the given MLIL instruction and traced variable,
    resolves its connected variable, and stores the taint information.

    Args:
        function_node (Function): The function containing the instruction.
        collected_locs (List[TaintedLOC]): The running list of collected taint locations.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction to associate with the taint.
        var_to_trace (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]):
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
                function_node=function_node,
                target_variable=var_to_trace,
            ),
            var_to_trace.confidence_level,
            function_node=function_node,
        )
    )


def find_load_store_data(
    mlil_loc,
    already_iterated: Union[list, set],
    analysis,
    var_to_trace=None,
    allow_append=True,
) -> Union[int, Variable, SSAVariable, None]:
    """
    Extracts address, offset, and tainted variable information from MLIL load/store instructions.

    Args:
        mlil_loc: The MediumLevelILInstruction representing a load or store operation.
        already_iterated (Union[list, set]): Collection of variables already identified as tainted.
        analysis: The analysis context or object.
        var_to_trace: (optional) The variable being specifically traced for taint.
        allow_append (bool): Whether to append new tainted variables to the tracking collection.

    Returns:
        LoadStoreData: An object containing the extracted offset, address variable, tainted offset variable,
        confidence level, and instruction address.
    """
    address_variable, var_offset = None, None
    tainted_offset_var = None
    addr_var = None
    offset = None

    if len(mlil_loc.dest.operands) == 1:
        addr_var = mlil_loc.dest.operands[0]

    elif len(mlil_loc.dest.operands) == 2:
        address_variable, var_offset = mlil_loc.dest.operands
        if isinstance(var_offset, MediumLevelILConst):
            addr_var = address_variable
            offset = var_offset
            var_offset = None
        else:
            addr_var_operands = address_variable.operands
            if len(addr_var_operands) == 2:
                addr_var, var_offset = addr_var_operands

            if isinstance(address_variable, MediumLevelILAddressOf):
                addr_var = address_variable.src
                offset = var_offset

            elif isinstance(var_offset, MediumLevelILVarSsa):
                addr_var, var_offset = mlil_loc.dest.operands
                var_offset = var_offset.var

            else:
                if len(address_variable.operands) == 2:
                    addr_var, offset = address_variable.operands

                elif (
                    len(address_variable.operands) == 1
                    and len(mlil_loc.dest.operands) == 2
                ):
                    addr_var, offset = mlil_loc.operands[0].vars_read

        if var_offset and not isinstance(var_offset, int):
            tainted_offset_var = [
                var.variable for var in already_iterated if var.variable == var_offset
            ]
            if not tainted_offset_var and allow_append:
                append_bingoggles_var_by_type(
                    var_offset, tainted_offset_var, mlil_loc, analysis, var_to_trace
                )
            if tainted_offset_var:
                tainted_offset_var = tainted_offset_var[0]

    return LoadStoreData(
        offset,
        addr_var,
        tainted_offset_var,
        var_to_trace.confidence_level if var_to_trace else TaintConfidence.Tainted,
        mlil_loc.address,
    )


def create_tainted_var_offset_from_load_store(
    mlil_loc,
    already_iterated: Union[list, set],
    analysis,
    var_to_trace=None,
) -> TaintedVarOffset:
    """
    Extracts relevant data from an MLIL load/store instruction and creates a TaintedVarOffset object.

    Args:
        mlil_loc: The MediumLevelILInstruction representing a load or store operation.
        already_iterated (Union[list, set]): A collection of variables that have already been identified as tainted
                                              or iterated through in the taint analysis.
        var_to_trace: An optional variable to specifically trace within the load/store operation.

    Returns:
        TaintedVarOffset: An object representing the tainted variable offset found in the load/store.
    """
    ls_data = None

    if var_to_trace:
        ls_data: LoadStoreData = find_load_store_data(
            mlil_loc, already_iterated, analysis, var_to_trace, allow_append=False
        )

    else:
        ls_data: LoadStoreData = find_load_store_data(
            mlil_loc, already_iterated, analysis, var_to_trace, allow_append=False
        )

    return TaintedVarOffset(
        ls_data.addr_var,
        ls_data.offset,
        ls_data.tainted_offset_var,
        ls_data.confidence_level,
        ls_data.loc_address,
    )


def create_tainted_global(
    analysis,
    global_var: MediumLevelILConstPtr,
    confidence_level: TaintConfidence,
    mlil_loc: MediumLevelILInstruction,
) -> Optional[TaintedGlobal]:
    """
    Creates a TaintedGlobal object if the given MLIL constant pointer resolves to a global symbol.

    Args:
        analysis: An analysis object containing the BinaryView (e.g., `analysis.bv`).
        global_var (MediumLevelILConstPtr): The MLIL constant pointer that might refer to a global variable.
        confidence_level (TaintConfidence): The confidence level of the taint.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction where the global variable is accessed.

    Returns:
        Union[None, TaintedGlobal]: A TaintedGlobal object if a symbol is found, otherwise None.
    """
    glob_symbol = get_symbol_from_const_ptr(analysis.bv, global_var)
    if glob_symbol:
        return TaintedGlobal(
            glob_symbol.name,
            confidence_level,
            mlil_loc.address,
            global_var,
            glob_symbol,
        )

    return None


def create_tainted_var(tainted_var, confidence_level, mlil_loc):
    """
    Creates a TaintedVar object representing a tainted variable.

    Args:
        tainted_var: The variable object (can be a Variable or SSAVariable-like object).
                     If it has a 'var' attribute (e.g., SSAVariable), that's used; otherwise,
                     the object itself is used.
        confidence_level (TaintConfidence): The confidence level of the taint.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction associated with this tainted variable.

    Returns:
        TaintedVar: An instance of the TaintedVar class.
    """
    return TaintedVar(
        tainted_var.var if hasattr(tainted_var, "var") else tainted_var,
        confidence_level,
        mlil_loc.address,
    )


def handle_tainted_var(
    tainted_var: Union[Variable, SSAVariable, MediumLevelILVar, MediumLevelILVarSsa],
    vars_found: Union[List, set],
    mlil_loc: MediumLevelILInstruction,
    var_to_trace=None,
):
    """
    Adds a tainted variable to the collection of found variables based on its type and tracing context.

    Args:
        tainted_var (Union[Variable, SSAVariable, MediumLevelILVar, MediumLevelILVarSsa]):
            The variable identified as tainted. It can be various forms of Binary Ninja variables.
        vars_found (Union[List, set]): The collection (list or set) to which the tainted variable will be added.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction where the taint was identified.
        var_to_trace: An optional object (e.g., TaintedVar) representing a specific variable being traced.
                      If provided, its `confidence_level` is used when adding to a list, and an additional
                      check `var_object != var_to_trace.variable` is performed.

    Returns:
        None: This function modifies `vars_found` in-place and does not return a value.
    """
    var_object = tainted_var.var if hasattr(tainted_var, "var") else tainted_var
    if var_to_trace and var_object != var_to_trace.variable:
        if isinstance(vars_found, list):
            vars_found.append(
                create_tainted_var(tainted_var, var_to_trace.confidence_level, mlil_loc)
            )

    elif isinstance(vars_found, set):
        vars_found.add(
            create_tainted_var(tainted_var, TaintConfidence.Tainted, mlil_loc)
        )


def handle_global_var(analysis, mlil_loc, tainted_var, vars_found, var_to_trace=None):
    """
    Adds a tainted global variable to the collection of found variables.

    Args:
        analysis: An analysis object containing the BinaryView (e.g., `analysis.bv`).
        mlil_loc (MediumLevelILInstruction): The MLIL instruction where the global variable is accessed.
        tainted_var: The variable representing the global variable (expected to be a MediumLevelILConstPtr or similar).
        vars_found (Union[list, set]): The collection (list or set) to which the tainted global variable will be added.
        var_to_trace: An optional object (e.g., TaintedVar) representing a specific variable being traced.
                      If provided, its `confidence_level` is used when adding to a list.

    Returns:
        None: This function modifies `vars_found` in-place and does not return a value.
    """
    if isinstance(vars_found, list) and var_to_trace:
        vars_found.append(
            create_tainted_global(
                analysis, tainted_var, var_to_trace.confidence_level, mlil_loc
            )
        )

    elif isinstance(vars_found, set):
        vars_found.add(
            create_tainted_global(
                analysis, tainted_var, TaintConfidence.Tainted, mlil_loc
            )
        )


def append_bingoggles_var_by_type(
    tainted_var: Union[Variable, MediumLevelILVar, MediumLevelILConstPtr],
    vars_found: Union[list, set],
    mlil_loc: MediumLevelILInstruction,
    analysis,
    var_to_trace: Union[
        TaintedStructMember, TaintedVar, TaintedGlobal, TaintedVarOffset
    ] = None,
) -> None:
    # check if vars_found is a set or list this will determine whether we're doing this for SSA interproc stuff or normal mlil stuff
    if not isinstance(vars_found, (list, set)):
        raise TypeError(
            f"Expected 'vars_found' to be a list or a set, but got {type(vars_found)}"
        )

    if isinstance(
        tainted_var, (MediumLevelILVar, Variable, SSAVariable, MediumLevelILVarSsa)
    ):
        if var_to_trace:
            handle_tainted_var(tainted_var, vars_found, mlil_loc, var_to_trace)
        else:
            handle_tainted_var(tainted_var, vars_found, mlil_loc)

    elif isinstance(tainted_var, MediumLevelILConstPtr):
        if var_to_trace:
            handle_global_var(analysis, mlil_loc, tainted_var, vars_found, var_to_trace)
        else:
            handle_global_var(analysis, mlil_loc, tainted_var, vars_found, var_to_trace)

    #:TODO
    elif mlil_loc.operation.value in [
        MediumLevelILOperation.MLIL_LOAD_SSA.value,
        MediumLevelILOperation.MLIL_LOAD.value,
        MediumLevelILOperation.MLIL_STORE.value,
        MediumLevelILOperation.MLIL_STORE_SSA.value,
    ]:
        if isinstance(vars_found, list):
            vars_found.append(
                create_tainted_var_offset_from_load_store(
                    mlil_loc,
                    vars_found,
                    var_to_trace,
                )
            )

        elif isinstance(vars_found, set):
            vars_found.add(
                create_tainted_var_offset_from_load_store(mlil_loc, vars_found)
            )

    #:TODO
    elif mlil_loc.operation.value in [
        MediumLevelILOperation.MLIL_STORE_STRUCT_SSA,
        MediumLevelILOperation.MLIL_STORE_STRUCT,
    ]:
        ...


def propagate_mlil_store_struct(
    function_node: Function,
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
        function_node: The Binary Ninja function context.
        mlil_loc: The MLIL instruction performing the store or assignment.
        collected_locs: List to track visited tainted locations.
        var_to_trace: The current tainted variable being traced.
        vars_found: Worklist of tainted variables to continue tracing.
        analysis: The main analysis object providing symbol, taint utilities and binary view
        trace_type: Direction of slicing (forward or backward).
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    decision = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_node,
        vars_found,
    )
    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.PROCESS_AND_DISCARD]:
        append_tainted_loc(
            function_node, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.SKIP_AND_PROCESS]:
        struct_offset = mlil_loc.ssa_form.offset
        instr_hlil = function_node.get_llil_at(mlil_loc.address).hlil

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

        elif mlil_loc.operation == MediumLevelILOperation.MLIL_SET_VAR.value:
            struct_offset = mlil_loc.ssa_form.src.offset
            source = mlil_loc.src
            source_hlil = instr_hlil.src

            if source.operation == MediumLevelILOperation.MLIL_LOAD_STRUCT.value:
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
    function_node: Function,
    mlil_loc: MediumLevelILInstruction,
    collected_locs: list,
    var_to_trace: Union[
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
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
        function_node (Function): The function containing the MLIL instruction.
        mlil_loc (MediumLevelILInstruction): The store instruction being analyzed.
        collected_locs (list): List of `TaintedLOC` objects visited during this trace.
        var_to_trace (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]):
            The variable from which taint is being propagated.
        vars_found (list): A list that will be updated with newly discovered tainted variables.
        already_iterated (list): A list of previously visited variables, used to determine taint propagation.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    decision = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_node,
        vars_found,
    )
    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.PROCESS_AND_DISCARD]:
        append_tainted_loc(
            function_node, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.SKIP_AND_PROCESS]:
        ls_data: LoadStoreData = find_load_store_data(
            mlil_loc, already_iterated, analysis, var_to_trace
        )
        if isinstance(ls_data.offset, MediumLevelILConstPtr):
            append_bingoggles_var_by_type(
                ls_data.offset, vars_found, mlil_loc, analysis, var_to_trace
            )
        else:
            append_bingoggles_var_by_type(
                ls_data.addr_var, vars_found, mlil_loc, analysis, var_to_trace
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
            append_bingoggles_var_by_type(
                t_var,
                vars_found,
                mlil_loc,
                analysis,
                var_to_trace,
            )

        if func_analyzed.taints_return:
            for t_var in mlil_loc.vars_written:
                append_bingoggles_var_by_type(
                    t_var,
                    vars_found,
                    mlil_loc,
                    analysis,
                    var_to_trace,
                )

    # Handle non-vararg function calls
    else:
        for t_src_indx in func_analyzed.taint_sources:
            for t_dst_indx in func_analyzed.taint_destinations:
                append_bingoggles_var_by_type(
                    mlil_loc.params[t_dst_indx],
                    vars_found,
                    mlil_loc,
                    analysis,
                    var_to_trace,
                )

        if func_analyzed.taints_return:
            for t_var in mlil_loc.vars_written:
                append_bingoggles_var_by_type(
                    t_var, vars_found, mlil_loc, analysis, var_to_trace
                )


def analyze_new_imported_function(
    mlil_loc: MediumLevelILInstruction,
    var_to_trace: Union[
        TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
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
        var_to_trace (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]):
            The original variable being traced for taint.
        vars_found (list): List of new tainted variables discovered via interprocedural analysis.
        analysis (Analysis): The main `Analysis` object handling taint propagation and resolution.
    """
    _, tainted_func_param = get_func_param_from_call_param(
        analysis.bv, mlil_loc, var_to_trace
    )

    call_func_object = addr_to_func(analysis.bv, mlil_loc.dest.value.value)

    if call_func_object:
        interproc_results = analysis.trace_function_taint(
            function_node=call_func_object,
            tainted_params=tainted_func_param,
            binary_view=analysis.bv,
        )

        if analysis.verbose:
            analysis.trace_function_taint_printed = False

        if interproc_results.is_return_tainted and mlil_loc.vars_written:
            if mlil_loc.vars_written:
                var_assigned = mlil_loc.vars_written[0]
                append_bingoggles_var_by_type(
                    var_assigned,
                    vars_found,
                    mlil_loc,
                    analysis,
                    var_to_trace,
                )

        if interproc_results.tainted_param_names:
            zipped_results = list(
                zip(
                    interproc_results.tainted_param_names,
                    mlil_loc.params,
                )
            )

            for _, var in zipped_results:
                append_bingoggles_var_by_type(
                    var, vars_found, mlil_loc, analysis, var_to_trace
                )


def propagate_mlil_call(
    function_node: Function,
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
        function_node (Function): The Binary Ninja function containing the call.
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
    decision = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_node,
        vars_found,
    )
    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.PROCESS_AND_DISCARD]:
        append_tainted_loc(
            function_node, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.SKIP_AND_PROCESS]:
        if mlil_loc.params:
            imported_function = analysis.resolve_function_type(mlil_loc)
            normalized_function_name = get_modeled_function_name_at_callsite(
                function_node, mlil_loc
            )

            func_analyzed = None
            if normalized_function_name:
                func_analyzed = analysis.analyze_function_taint(
                    normalized_function_name, var_to_trace, mlil_loc
                )

            elif imported_function:
                func_analyzed = analysis.analyze_function_taint(
                    imported_function, var_to_trace, mlil_loc
                )

            elif not normalized_function_name and not imported_function:
                resolved_function_object = resolve_got_callsite(
                    function_node.view, mlil_loc.dest.value.value
                )

                if resolved_function_object:
                    func_analyzed = analysis.analyze_function_taint(
                        resolved_function_object.name, var_to_trace, mlil_loc
                    )

                else:
                    _, tainted_func_param = get_func_param_from_call_param(
                        analysis.bv, mlil_loc, var_to_trace
                    )

                    call_func_object = addr_to_func(
                        analysis.bv, mlil_loc.dest.value.value
                    )

                    if call_func_object:
                        func_analyzed = analysis.trace_function_taint(
                            function_node=call_func_object,
                            tainted_params=tainted_func_param,
                            binary_view=analysis.bv,
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

                for tainted_function_param, call_param in zipped_results:
                    # Wrap each tainted parameter into the appropriate BinGoggles taint type
                    append_bingoggles_var_by_type(
                        call_param, vars_found, mlil_loc, analysis, var_to_trace
                    )

                if func_analyzed.is_return_tainted:
                    if mlil_loc.vars_written:
                        # If return value is tainted, treat it as a new tainted variable
                        append_bingoggles_var_by_type(
                            mlil_loc.vars_written[0],
                            vars_found,
                            mlil_loc,
                            analysis,
                            var_to_trace,
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

    if hasattr(mlil_loc.src, "vars_read") and mlil_loc.src.vars_read:
        source_read_vars = mlil_loc.src.vars_read
        if source_read_vars:
            return any(isinstance(var, Variable) for var in source_read_vars)

    else:
        return False


def propagate_mlil_set_var(
    function_node: Function,
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
        function_node (Function): The Binary Ninja function containing the instruction.
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
    decision = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_node,
        vars_found,
    )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.PROCESS_AND_DISCARD]:
        append_tainted_loc(
            function_node, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.SKIP_AND_PROCESS]:

        variable_written_to = mlil_loc.vars_written[0]
        variable_read_from = None

        if mlil_loc.vars_read:
            variable_read_from = mlil_loc.vars_read[0]

        if isinstance(mlil_loc.src, MediumLevelILLoad) or isinstance(
            mlil_loc.dest, MediumLevelILLoad
        ):
            if isinstance(mlil_loc.src, MediumLevelILLoad):
                try:
                    address_variable, var_offset = mlil_loc.src.vars_read

                except ValueError:
                    address_variable = mlil_loc.src.vars_read[0]
                    var_offset = None

            else:
                address_variable, var_offset = mlil_loc.dest.vars_written

            offset_var_taintedvar = None
            if var_offset:
                offset_var_taintedvar = [
                    var.variable
                    for var in already_iterated
                    if var.variable == var_offset
                ]

            if offset_var_taintedvar:
                vars_found.append(
                    TaintedVarOffset(
                        variable=address_variable,
                        offset=None,
                        offset_var=offset_var_taintedvar[0],
                        confidence_level=var_to_trace.confidence_level,
                        loc_address=mlil_loc.address,
                    )
                )

            if variable_written_to:
                append_bingoggles_var_by_type(
                    variable_written_to,
                    vars_found,
                    mlil_loc,
                    analysis,
                    var_to_trace,
                )

        elif variable_written_to:
            append_bingoggles_var_by_type(
                variable_written_to, vars_found, mlil_loc, analysis, var_to_trace
            )

        if variable_read_from:
            if add_read_var(mlil_loc):
                append_bingoggles_var_by_type(
                    variable_read_from,
                    vars_found,
                    mlil_loc,
                    analysis,
                    var_to_trace,
                )


def propagate_mlil_set_var_field(
    function_node: Function,
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
        function_node (Function): The Binary Ninja function containing the instruction.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction performing the field assignment.
        vars_found (list): Queue of tainted variables to be analyzed.
        var_to_trace: The original tainted variable being traced.
        collected_locs (List[TaintedLOC]): Accumulated list of tainted instruction locations.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    decision = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_node,
        vars_found,
    )
    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.PROCESS_AND_DISCARD]:
        append_tainted_loc(
            function_node, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.SKIP_AND_PROCESS]:
        append_bingoggles_var_by_type(
            mlil_loc.dest, vars_found, mlil_loc, analysis, var_to_trace
        )


def propagate_mlil_unhandled_operation(
    function_node: Function,
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
        function_node (Function): The Binary Ninja function containing the instruction.
        mlil_loc (MediumLevelILInstruction): The MLIL instruction to analyze.
        vars_found (list): Worklist queue to which new tainted variables are added.
        var_to_trace: The current tainted variable being traced.
        collected_locs (List[TaintedLOC]): List of tainted locations recorded so far.
        analysis (Analysis): The analysis engine (BinGoggles `Analysis` class).
        trace_type (SliceType): Indicates whether the taint trace is forward or backward.
        first_mlil_loc (MediumLevelILInstruction): The initial MLIL instruction that began the trace.
            Used for controlling trace range and instruction relevance based on direction.
    """
    decision = skip_instruction(
        mlil_loc,
        first_mlil_loc,
        var_to_trace,
        trace_type,
        analysis,
        function_node,
        vars_found,
    )
    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.PROCESS_AND_DISCARD]:
        append_tainted_loc(
            function_node, collected_locs, mlil_loc, var_to_trace, analysis
        )

    if decision in [TraceDecision.PROCESS_AND_TRACE, TraceDecision.SKIP_AND_PROCESS]:
        if mlil_loc.vars_written and is_rw_operation(mlil_loc):
            for variable_written_to in mlil_loc.vars_written:
                append_bingoggles_var_by_type(
                    variable_written_to, vars_found, mlil_loc, analysis, var_to_trace
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
    function_node: Function,
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
        function_node (Function): The Binary Ninja function containing the instruction.
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
    match mlil_loc.operation.value:
        case MediumLevelILOperation.MLIL_STORE_STRUCT.value:
            propagate_mlil_store_struct(
                function_node,
                mlil_loc,
                collected_locs,
                var_to_trace,
                vars_found,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case MediumLevelILOperation.MLIL_STORE.value:
            propagate_mlil_store(
                function_node,
                mlil_loc,
                collected_locs,
                var_to_trace,
                vars_found,
                already_iterated,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case MediumLevelILOperation.MLIL_CALL.value:
            propagate_mlil_call(
                function_node,
                mlil_loc,
                collected_locs,
                var_to_trace,
                vars_found,
                already_iterated,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case MediumLevelILOperation.MLIL_SET_VAR.value:
            propagate_mlil_set_var(
                function_node,
                mlil_loc,
                vars_found,
                already_iterated,
                var_to_trace,
                collected_locs,
                analysis,
                trace_type,
                first_mlil_loc,
            )

        case MediumLevelILOperation.MLIL_SET_VAR_FIELD.value:
            propagate_mlil_set_var_field(
                function_node,
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
                function_node,
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
    function_node: Function,
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
        function_node (Function): The Binary Ninja function object where the variable resides.
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
            var_to_trace, function_node, analysis
        )

        for ref in variable_use_sites:
            instr_mlil = function_node.get_llil_at(ref.address).mlil
            propagate_by_mlil_operation(
                function_node,
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
    function_node: Function, var_name: str, ssa_form: bool = False
):
    """
    Get the variable object for a parameter in a function based on a string variable name.

    Args:
        function_node (Function): Binary Ninja function object.
        var_name (str): Name of the variable as a string.
        ssa_form (bool): Whether to return the SSA form of the variable.

    Returns:
        Variable or SSAVariable: The corresponding variable object.
    """
    if ssa_form:
        # Access the Medium Level IL (MLIL) SSA form of the function
        mlil_ssa = function_node.mlil.ssa_form
        if mlil_ssa is None:
            raise ValueError(
                f"SSA form is not available for function {function_node.name}"
            )

        # Iterate through SSA variables to find the matching one
        for ssa_var in mlil_ssa.ssa_vars:
            if ssa_var.var.name == var_name:
                return ssa_var

        raise ValueError(
            f"SSA form of variable '{var_name}' not found in function {function_node.name}"
        )

    else:
        # Access the regular parameters of the function
        parameters = function_node.parameter_vars
        for param in parameters:
            if param.name == var_name:
                return param

        raise ValueError(
            f"Parameter '{var_name}' not found in function {function_node.name}"
        )


def str_to_var_object(
    var_as_str: str | MediumLevelILVar, function_node: Function
) -> Optional[Variable]:
    """
    Converts a variable name or MediumLevelILVar into a Binary Ninja Variable object.
    Searches the function's variable list for a match by name. If a MediumLevelILVar is passed,
    its `.name` is extracted and used for matching.

    Args:
        var_as_str (str | MediumLevelILVar): The variable name or MLIL variable to resolve.
        function_node (Function): The Binary Ninja function containing the variable.

    Returns:
        Variable | None: The matching Variable object, or None if not found.
    """
    var_object = None

    if isinstance(var_as_str, MediumLevelILVar):
        var_as_str = var_as_str.name

    for var in function_node.vars:
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
    """
    function_node = addr_to_func(bv, instr_mlil.dest.value.value)
    if function_node:
        call_params = [
            v.var if isinstance(v, (MediumLevelILVar, MediumLevelILVarSsa)) else None
            for v in instr_mlil.params
        ]
        function_params = [
            v if isinstance(v, (Variable, SSAVariable)) else None
            for v in function_node.parameter_vars
        ]
        mapped = dict(zip(call_params, function_params))
        var_object = None

        if not isinstance(
            var_to_trace,
            (TaintedVar, TaintedGlobal, TaintedStructMember, TaintedVarOffset),
        ):
            var_object = var_to_trace
        else:
            var_object = var_to_trace.variable

        tainted_func_param = None

        for call_param, func_param in mapped.items():
            if call_param == var_object:
                tainted_func_param = func_param

        return mapped, tainted_func_param

    else:
        return None, None


def get_use_sites(
    loc: MediumLevelILInstruction,
    var: Union[MediumLevelILVar, MediumLevelILVarSsa, SSAVariable, Variable],
) -> Optional[list]:
    """
    Retrieve the use sites of a specific variable within a given MLIL instruction.

    Args:
        loc (MediumLevelILInstruction): The MLIL instruction to inspect.
        var (Union[MediumLevelILVar, MediumLevelILVarSsa, SSAVariable, Variable]): The variable whose use sites are to be found.

    Returns:
        list | None: The use sites of the variable if found in the instruction, otherwise None.
    """
    vars = []
    if hasattr(loc, "vars_written"):
        vars.extend(loc.vars_written)
    if hasattr(loc, "vars_read"):
        vars.extend(loc.vars_read)
    for v in vars:
        if isinstance(var, (MediumLevelILVar, MediumLevelILVarSsa)):
            var = var.var
        if v.name == var.name:
            return v.use_sites


def tainted_param_in_model_sources(
    function_model: FunctionModel,
    loc: MediumLevelILInstruction,
    tainted_param: Variable,
) -> bool:
    """
    Determines if the given tainted parameter is among the modeled taint sources for a function call.

    Args:
        function_model (FunctionModel): The function model describing taint sources and vararg index.
        loc (MediumLevelILInstruction): The MLIL call instruction containing the call parameters.
        tainted_param (Variable): The variable to check for taint source status.

    Returns:
        bool: True if the parameter is a taint source according to the model, False otherwise.
    """
    call_parameters: List[Variable] = [
        v.var if isinstance(v, (MediumLevelILVar, MediumLevelILVarSsa)) else None
        for v in loc.params
    ]
    tainted_index = call_parameters.index(
        tainted_param.variable if hasattr(tainted_param, "variable") else tainted_param
    )
    if function_model.vararg_start_index:
        if tainted_index > function_model.vararg_start_index:
            return True

    if tainted_index in function_model.taint_sources:
        return True

    return False


def get_ssa_variable(func, var: Union[SSAVariable, Variable, str]) -> SSAVariable:
    """
    Retrieves the SSA form of a given variable within a function.

    Args:
        func: The function object (e.g., Binary Ninja Function).
        var (Variable): The variable to convert to SSA form.

    Returns:
        SSAVariable: The SSA form of the variable, or None if not found.
    """
    if isinstance(var, SSAVariable):
        return var

    if isinstance(var, Variable):
        var = var.name

    for ssa_var in func.mlil.ssa_form.vars:
        if ssa_var.var.name == var:
            return ssa_var.var
