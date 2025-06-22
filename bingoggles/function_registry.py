from bingoggles_types import FunctionModel
from typing import Union

modeled_functions = [
    FunctionModel("strcpy", [1], [0], True),
    FunctionModel("strncpy", [1], [0], True),
    FunctionModel("memcpy", [1], [0], True),
    FunctionModel("wcscpy", [1], [0], True),
    FunctionModel("fgets", [2], [0], True),
    FunctionModel("read", [0], [1], True),
    FunctionModel("recv", [0], [1], True),
    FunctionModel("gets", [], [0], True),
    FunctionModel(
        name="realloc",
        taint_sources=[0],
        taint_destinations=[],
        taints_return=True,
    ),
    FunctionModel("getdelim", [3], [0], True),
    FunctionModel("getline", [2], [0], True),
    FunctionModel("sscanf", [0], [2], False),
    FunctionModel("scanf", [], [1], False),
    FunctionModel(
        name="snprintf",
        taint_sources=[],
        taint_destinations=[0],
        taints_return=True,
        taints_varargs=True,
        vararg_start_index=3,
    ),
]


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

    This includes:
    - '__builtin_' for compiler intrinsics (e.g., '__builtin_strcpy' → 'strcpy')
    - '__' for glibc internal aliases (e.g., '__getdelim' → 'getdelim')
    - '_' for lightly mangled names (e.g., '_strncpy' → 'strncpy')

    Args:
        name (str): The raw function name as seen in the binary.

    Returns:
        str: A normalized function name suitable for lookup in the libc taint model.
    """
    for prefix in ("__builtin_", "__", "_", "__isoc99_"):
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
