from .bingoggles_types import FunctionModel
from typing import Union
from binaryninja import Function, MediumLevelILInstruction, SymbolType
from functools import cache


modeled_functions = [
    FunctionModel("strcpy", [1], [0], True),
    FunctionModel("strncpy", [1], [0], True),
    FunctionModel("stpcpy", [1], [0], True),
    FunctionModel("strlcpy", [1], [0], True),
    FunctionModel("wcscpy", [1], [0], True),
    FunctionModel("wcsncpy", [1], [0], True),
    FunctionModel("memcpy", [1], [0], True),
    FunctionModel("memmove", [1], [0], True),
    FunctionModel("wmemcpy", [1], [0], True),
    FunctionModel("strcat", [1], [0], True),
    FunctionModel("strncat", [1], [0], True),
    FunctionModel("strlcat", [1], [0], True),
    FunctionModel("wcscat", [1], [0], True),
    FunctionModel("wcsncat", [1], [0], True),
    FunctionModel("fgets", [2], [0], True),
    FunctionModel("fgets_unlocked", [2], [0], False),
    FunctionModel("fgetws_unlocked", [2], [0], False),
    FunctionModel("read", [0], [1], True),
    FunctionModel("recv", [0], [1], True),
    FunctionModel("gets", [0], [], True),
    FunctionModel("strlen", [0], [], True),
    FunctionModel("realloc", [0], [], True),
    FunctionModel("getdelim", [3], [0], True),
    FunctionModel("getline", [2], [0], True),
    FunctionModel("recvfrom", [1], [0], True),
    FunctionModel("recvmsg", [1], [0], True),
    FunctionModel("fopen", [0, 1], [], True),
    FunctionModel("freopen", [0, 1, 2], [], True),
    FunctionModel("fdopen", [0, 1], [], True),
    FunctionModel("opendir", [0], [], True),
    FunctionModel("fdopendir", [0], [], True),
    FunctionModel("fread", [3], [0], True),
    FunctionModel("scanf", [], [], False, True, 1),
    FunctionModel("fscanf", [], [], False, True, 2),
    FunctionModel("sscanf", [0], [2], False, True, 2),
    FunctionModel("vscanf", [], [], False, True, 1),
    FunctionModel("vfscanf", [], [], False, True, 3),
    FunctionModel("vsscanf", [0], [2], False, True, 2),
    FunctionModel("wprintf", [], [0], True, True, 1),
    FunctionModel("fwprintf", [], [0], True, True, 2),
    FunctionModel("swprintf", [], [0], True, True, 3),
    FunctionModel("vwprintf", [], [0], True, True, 2),
    FunctionModel("vfwprintf", [], [0], True, True, 3),
    FunctionModel("vswprintf", [], [0], True, True, 3),
    FunctionModel("snprintf", [], [0], True, True, 3),
    FunctionModel("sprintf", [], [0], True, True, 2),
    FunctionModel("vsprintf", [], [0], True, True, 2),
    FunctionModel("swscanf", [0], [2], False, True, 2),
    # we're adding functions here that dont taint anything, we dont want to do any analysis on them.
    FunctionModel("printf", [], [], False, False, 1),
]

modeled_functions_names = [i.name for i in modeled_functions]


def get_modeled_function_index(name: str) -> int | None:
    """
    Retrieve the index of a modeled function by its name.

    This function searches through the global `modeled_functions` list and returns
    the index of the first FunctionModel object whose `name` attribute matches the given name.

    Parameters:
        name (str): The name of the function to search for.

    Returns:
        int | None: The index of the matching function if found, otherwise None.
    """
    for i, model in enumerate(modeled_functions):
        if model.name == name:
            return i
    return None


def normalize_func_name(name: str) -> str:
    """
    Normalize a function name by stripping common compiler or internal prefixes.

    Args:
        name (str): The raw function name as seen in the binary.

    Returns:
        str: A normalized function name suitable for lookup in the libc taint model.
    """
    common_prefixes = [
        "__builtin_",  # Binja builtins (e.g., __builtin_memcpy)
        "__libc_",  # GNU C Library internals
        "__GI_",  # GNU C Library Global Internal
        "_imp__",  # Windows import thunks (e.g., _imp__printf)
        "__isoc99_",  # ISO C99 specifics
        "_IO_",  # Standard I/O library internals (e.g., _IO_getc)
        "__new_",  # Related to new operator
        "__",  # Double underscore (general compiler/internal)
        "_",  # Single underscore (general, often for internal or static)
    ]
    for prefix in common_prefixes:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def get_function_model(name: str) -> Union[FunctionModel, None]:
    """
    Retrieve a taint model for a given libc-style function name.

    This performs name normalization to account for intrinsics and internal aliases
    (e.g., '__builtin_strcpy', '__getdelim') before matching against the known set
    of taint-relevant libc functions.

    Args:
        name (str): A function name from disassembly or symbol analysis.

    Returns:
        FunctionModel | None: The associated taint model if known, else None.
    """
    normalized = normalize_func_name(name)
    for func in modeled_functions:
        if func.name == normalized:
            return func
    return None

@cache
def get_modeled_function_name_at_callsite(
    function_object: Function, mlil_loc: MediumLevelILInstruction
) -> Union[str, None]:
    """
    Given an MLIL call instruction, return the normalized name of the called function
    if it matches one of the known modeled functions.

    This function extracts the function being called at the provided MLIL instruction,
    normalizes its name using `normalize_func_name`, and checks if it exists in the
    list of modeled functions. If so, the normalized name is returned.

    Args:
        function_object (Function): The Binary Ninja Function object containing the MLIL instruction.
        mlil_loc (MediumLevelILInstruction): The MLIL call instruction where the function is invoked.

    Returns:
        str | None: The normalized name of the matched modeled function, or None if no match is found.
    """
    bv = function_object.view
    function = bv.get_function_at(mlil_loc.dest.value.value)
    function_name = None
    if function:
        function_name = function.name
        normalized_name = normalize_func_name(function_name)
        if normalized_name in [func.name for func in modeled_functions]:
            return normalized_name

    start = bv.get_section_by_name(".synthetic_builtins").start
    end = bv.get_section_by_name(".synthetic_builtins").end
    symbol = bv.get_symbol_at(mlil_loc.dest.value.value)
    if symbol and symbol.type.value == SymbolType.SymbolicFunctionSymbol.value:
        function_name = bv.get_symbol_at(mlil_loc.dest.value.value).name

        for addr in range(start, end, 8):
            builtin_function = bv.get_symbol_at(addr)
            if builtin_function and builtin_function.name == function_name:
                normalized_builtin_name = normalize_func_name(builtin_function.name)
                if normalized_builtin_name in [func.name for func in modeled_functions]:
                    return normalized_builtin_name

    return None
