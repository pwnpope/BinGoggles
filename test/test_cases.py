"""
BinGoggles Taint Analysis Test Suite
====================================

This file contains integration tests for BinGoggles' taint tracking and slicing logic.

It covers:
- Forward and backward taint propagation
- Interprocedural slicing
- Detection of vulnerable patterns (e.g., use-after-free)
- Global variable and struct member tracking
- Parameter taint inference and function call tracing

Binaries under test are compiled with uClibc.
See `test/README.txt` for detailed information on the compilation configuration and how to reproduce or run these tests.

Note: These tests assume Buildroot output exists in `test/buildroot/output/` and that the relevant binaries are present under `test/binaries/bin/`.
"""

from os.path import abspath
from pprint import pprint

from bingoggles.bg import Analysis, VargFunctionCallResolver
from bingoggles.bingoggles_types import *
from bingoggles.modules import *
import os
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=None)
def find_dir(root_path: str, target_name: str) -> str | None:
    """
    Recursively search for a directory named `target_name` under `root_path`,
    and cache the result for future calls.

    Parameters:
        root_path (str): Base path to begin the search.
        target_name (str): Directory name to search for.

    Returns:
        str | None: Full path to the matched directory, or None if not found.
    """
    for dirpath, dirnames, _ in os.walk(root_path):
        if target_name in dirnames:
            return os.path.join(dirpath, target_name)
    return None


bingoggles_path = Path(__file__).parent


def get_bndb_path_or_original(file_path: str) -> str:
    """
    Determines the correct path to use, prioritizing an existing .bndb file.

    Args:
        file_path (str): The original path to a binary file or a .bndb file.

    Returns:
        str: The path to an existing .bndb file if found, otherwise the original file_path.
    """
    if file_path.lower().endswith(".bndb") and os.path.isfile(file_path):
        return file_path

    potential_bndb_path = f"{file_path}.bndb"

    if os.path.isfile(potential_bndb_path):
        return potential_bndb_path

    return file_path


def test_backwards_slice_var(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_mlil_store.bndb"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    tainted_locs, func_name, tainted_vars = analysis.tainted_slice(
        #     22 @ 004018dc  [&var_35 + rax_7].b = rdx_1
        target=TaintTarget(0x004018DC, "rdx_1"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Backward,
    )

    pprint(tainted_locs)

    pprint(tainted_vars)
    assert len(tainted_locs) > 0, "No tainted locations found"
    assert (
        len(tainted_locs) == 12
    ), f"Expected 12 tainted locations, but got {len(tainted_locs)}"


def test_fwd_slice_param(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_slices.bndb"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    sliced_data, _, tainted_vars = analysis.tainted_slice(
        # 00401915    void* test_var_1(int a)
        target=TaintTarget(0x00401915, "a"),
        var_type=SlicingID.FunctionParam,
        output=OutputMode.Returned,
    )

    pprint(tainted_vars)
    assert len(sliced_data) > 0, "No tainted locations found"
    assert (
        len(sliced_data) == 14
    ), f"Expected 14 tainted locations, but got {len(sliced_data)}"


def test_fwd_slice_var(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_mlil_store"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    sliced_data, _, tainted_vars = analysis.tainted_slice(
        target=TaintTarget(0x00401897, "var_2b"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(tainted_vars)
    expected_instr_indexes = {
        6,
        11,
        12,
        13,
        14,
        17,
        18,
        19,
        22,
    }

    actual_instr_indexes = {tainted.loc.instr_index for tainted in sliced_data}

    missing = expected_instr_indexes - actual_instr_indexes
    unexpected = actual_instr_indexes - expected_instr_indexes

    assert not missing, f"Missing expected instruction indexes: {sorted(missing)}"
    assert not unexpected, f"Unexpected instruction indexes found: {sorted(unexpected)}"


def test_get_sliced_calls(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_get_sliced_calls"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    sliced_data, func_name, propagated_vars = analysis.tainted_slice(
        #   7 @ 0040196d  rsi = &a
        target=TaintTarget(0x0040196D, "a"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(propagated_vars)
    result = analysis.get_sliced_calls(
        tuple(sliced_data), func_name, tuple(propagated_vars)
    )

    assert len(result) == 4
    pprint(result)


def test_complete_bkd_slice_var(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_backwards_slice"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    data = analysis.complete_slice(
        target=TaintTarget(0x08049325, "var_13c"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Backward,
    )

    assert any(entry[0] == "main" for entry in data)

    main_entry = next(entry for entry in data if entry[0] == "main")
    assert "var_13c" in str(main_entry[1])

    main_trace, _ = data[main_entry]

    main_instr_indexes = {entry.loc.instr_index for entry in main_trace}
    assert main_instr_indexes >= {
        15,
        17,
    }, f"Missing expected instrs in main: {main_instr_indexes}"


def test_complete_fwd_slice_var(
    bg_init,
    test_bin=get_bndb_path_or_original(f"{bingoggles_path}/binaries/bin/test_uaf"),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        # 080498c6        char* buffer = malloc(0x64)
        target=TaintTarget(0x080498C6, "buffer"),
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Forward,
    )

    expected_funcs = {"level_eight", "deeper_and_deeper", "deeper_function", "do_free"}
    actual_funcs = {fn for (fn, _) in data.keys()}
    for fn in expected_funcs:
        assert fn in actual_funcs, f"Expected function '{fn}' in taint trace"

    expected_instrs = {
        "level_eight": {0, 1, 2, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16},
        "deeper_and_deeper": {1, 2, 3},
        "deeper_function": {1, 2, 3},
        "do_free": {1, 2},
    }

    for (fn, var), (trace_entries, _) in data.items():
        instr_indexes = {entry.loc.instr_index for entry in trace_entries}

        assert instr_indexes, f"No instructions recorded for function '{fn}'"

        if fn in expected_instrs:
            missing = expected_instrs[fn] - instr_indexes
            if missing:
                print(f"[WARN] {fn} missing expected instr indexes: {missing}")
            else:
                print(f"[INFO] {fn} includes all expected instruction indexes.")

            for expected_index in expected_instrs[fn]:
                assert expected_index in instr_indexes, (
                    f"Function '{fn}' is missing expected instruction index {expected_index}. "
                    f"Found instruction indexes: {instr_indexes}"
                )


def test_complete_fwd_slice_param(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_is_param_tainted"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()
    analysis = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)

    # Slice the second parameter 'b'
    data = analysis.complete_slice(
        target=TaintTarget(0x0804933C, "b"),
        var_type=SlicingID.FunctionParam,
        slice_type=SliceType.Forward,
    )

    # Validate presence of functions
    expected_funcs = {"do_calculation_and_write_to_buf", "do_math"}
    assert expected_funcs.issubset(
        {key[0] for key in data}
    ), f"Expected functions {expected_funcs} not all present in result keys"

    # Flatten locations and vars
    all_locs = []
    all_vars = []
    for (func, _), (locs, vars_) in data.items():
        all_locs.extend(locs)
        all_vars.extend(vars_)

    # Basic propagation check
    assert len(all_locs) >= 10, f"Expected ≥10 propagation steps, got {len(all_locs)}"

    # Check that specific variables were tainted
    expected_var_names = {"b", "eax", "edx", "eax_2", "result", "eax_4"}
    found_var_names = {str(var.variable) for var in all_vars}
    assert expected_var_names.issubset(
        found_var_names
    ), f"Expected tainted vars {expected_var_names}, got {found_var_names}"

    pprint(data)


def test_is_param_tainted(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_is_param_tainted"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    # 0x080492f7    void* my_strcpy(char* d, char* s)
    data = aux.trace_function_taint(
        function_node=0x080492F7,
        tainted_params=tuple(["s"]),
    )

    assert data.is_return_tainted is True

    # Parameter names should include both 'd' and 's'
    param_names = {v.name for v in data.tainted_param_names}
    assert "d" in param_names
    assert "s" in param_names
    assert len(param_names) == 2

    print(data)


def test_global_tracking_fwd_var(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_global_tracking"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()
    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    locs, _, tainted_vars = aux.tainted_slice(
        #    9 @ 08049302  strcpy(&glob_buf, var_12c)
        target=TaintTarget(0x08049302, "glob_buf"),
        var_type=SlicingID.FunctionVar,
    )

    assert (
        locs is not None and len(locs) > 0
    ), "No tainted LOCs found for global variable"
    assert any(
        "strcpy" in str(loc) for loc in locs
    ), "strcpy should be part of taint path"
    assert any(
        "printf" in str(loc) for loc in locs
    ), "printf should be part of taint path"
    assert any(
        "glob_buf" in str(var.variable) for var in tainted_vars
    ), "glob_buf not in tainted variables"


def test_uaf(
    bg_init,
    test_bin=get_bndb_path_or_original(f"{bingoggles_path}/binaries/bin/test_uaf"),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    test_case = input("Which UAF test case would you like to run? (1-8): ")

    match test_case:
        case "1":
            # Testing a basic Use-After-Free (UAF) where memory is allocated, freed, and then accessed.
            # (VULNERABLE):     0 @ 08049240  eax = malloc(0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x08049240, "eax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )

            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 4
            ), "Expected 4 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "2":
            # Testing a UAF using realloc with size 0 (effectively freeing the memory), then accessing the freed memory.
            # (VULNERABLE):     0 @ 080492dd  eax = malloc(0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x080492DD, "eax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )

            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 5
            ), "Expected 5 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "3":
            # No vulnerability, testing for safe usage of allocated memory without freeing it prematurely.
            # (SAFE):    0 @ 0804937f  eax = malloc(0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x0804937F, "eax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            assert vulns is None, "Expected None"

            print(f"[{Fore.GREEN}SAFE{Fore.GREEN}]: No UAF detected.")

        case "4":
            # Testing UAF where memory is freed and then accessed across function boundaries.
            # (VULNERABLE):   0 @ 0804947b  eax = malloc(0x64) [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x0804947B, "eax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 6
            ), "Expected 6 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "5":
            # Demonstrating UAF where a buffer is freed in one function and then accessed in another function.
            # (VULNERABLE):   0 @ 0804955b  buffer = malloc(0x64) [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x0804955B, "buffer"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 4
            ), "Expected 4 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "6":
            # UAF where memory is reallocated but used after being freed by realloc.
            # (VULNERABLE):   0 @ 0804960e  eax = malloc(0x64) [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x0804960E, "eax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 9
            ), "Expected 9 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "7":
            # Safe usage of memory where allocated memory is correctly freed and reallocated.
            # (SAFE):   0 @ 08049716  eax = malloc(0x64)  [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x08049716, "eax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()

            assert vulns is None, f"Expected None, but got {type(vulns).__name__}"

            print(f"[{Fore.GREEN}SAFE{Fore.RESET}]: No UAF detected.")

        case "8":
            # Deep sub-function frees buffer and then reuses the memory in the parent function
            # (VULNERBLE):   0 @ 080498c6  buffer = malloc(0x64) [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x080498C6, "buffer"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            assert vulns
            assert (
                len(vulns[0].vulnerable_path_data) == 4
            ), "Expected 4 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vulns[0].vulnerable_path_data])


def test_load_struct(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_struct_member"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    locs, _, tainted_vars = aux.tainted_slice(
        target=TaintTarget(0x0804922D, "ptr"),
        var_type=SlicingID.StructMember,
    )
    expected_instrs = [3, 5, 6, 8, 9, 11, 12, 14, 38, 39, 40, 50, 51, 52]
    for i in locs:
        assert i.loc.instr_index == expected_instrs.pop(0)

    pprint(tainted_vars)


def test_set_var_field(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_struct_member"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    locs, _, tainted_vars = aux.tainted_slice(
        #    5 @ 0x080493a8  eax = myStruct.ptr
        target=TaintTarget(0x080493A8, "ptr"),
        var_type=SlicingID.StructMember,
    )

    pprint(tainted_vars)
    instr_indexes = set([loc.loc.instr_index for loc in locs])
    expected_indexes = [5, 6, 7, 8]

    missing = set(expected_indexes) - instr_indexes
    assert not missing, f"Missing expected instruction indexes: {sorted(missing)}"
    for i in locs:
        assert expected_indexes.pop(0) == i.loc.instr_index


def test_interproc_memcpy(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_function_param_tainted_memcpy"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    _, _, tainted_vars = aux.tainted_slice(
        #   34 @ 004019ef  rdi_1 = &var_158
        target=TaintTarget(0x004019EF, "var_158"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(tainted_vars)
