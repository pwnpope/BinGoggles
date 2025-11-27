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

from bingoggles.bg import Analysis
from bingoggles.bingoggles_types import *
from bingoggles.modules import *
import os
from functools import lru_cache
from pathlib import Path
import pytest


# Add a fixture to support both headless modes
@pytest.fixture
def bg_init(request):
    """
    Pytest fixture that provides either BGInit or BGInitRpyc based on --rpyc flag.
    
    Usage:
        pytest -s test_cases.py::test_name                  # Uses BGInit (standard)
        pytest -s --rpyc test_cases.py::test_name           # Uses BGInitRpyc (hugsy headless)
    """
    use_rpyc = request.config.getoption("--rpyc", default=False)
    
    if use_rpyc:
        def _init(target_bin, libraries):
            return BGInitRpyc(target_bin=target_bin, libraries=libraries)
    else:
        def _init(target_bin, libraries):
            return BGInit(target_bin=target_bin, libraries=libraries)
    
    return _init


# Configure pytest to accept --rpyc argument
def pytest_addoption(parser):
    """Add custom command line option for rpyc mode."""
    parser.addoption(
        "--rpyc",
        action="store_true",
        default=False,
        help="Use rpyc (hugsy headless) instead of standard Binary Ninja headless"
    )

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
    # test_bin=get_bndb_path_or_original(
    #     f"{bingoggles_path}/binaries/bin/test_mlil_store.bndb"
    # ),
):
    test_bin = get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_mlil_store.bndb"
    )
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

    print(tainted_locs, tainted_vars)
    assert len(tainted_locs) > 0, "No tainted locations found"
    assert (
        len(tainted_locs) == 11
    ), f"Expected 11 tainted locations, but got {len(tainted_locs)}"

    # Check that we found the expected instruction indexes
    expected_instr_indexes = {4, 5, 6, 11, 12, 13, 14, 17, 18, 19, 22}
    actual_instr_indexes = {loc.loc.instr_index for loc in tainted_locs}

    assert actual_instr_indexes == expected_instr_indexes, (
        f"Expected instruction indexes {expected_instr_indexes}, "
        f"but got {actual_instr_indexes}"
    )

    # Check specific critical instructions are present
    assert any(
        loc.loc.instr_index == 6 for loc in tainted_locs
    ), "Missing strncpy instruction"
    assert any(
        loc.loc.instr_index == 17 for loc in tainted_locs
    ), "Missing memory read from var_2b"
    assert any(
        loc.loc.instr_index == 22 for loc in tainted_locs
    ), "Missing target instruction"

    # Check that var_2b is in tainted variables (it's the key data source)
    var_names = {str(var.variable) for var in tainted_vars}
    assert "var_2b" in var_names, f"var_2b should be in tainted variables: {var_names}"

    print(f"✓ Backward slice correctly found {len(tainted_locs)} locations")
    print(f"✓ All expected instruction indexes present: {sorted(actual_instr_indexes)}")


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

    assert sliced_data and len(sliced_data) > 0, "No tainted locations found"

    expected_instr_indexes = {
        0,
        9,
        10,
        11,
        19,
        20,
        21,
        29,
        30,
        31,
        33,
        34,
        36,
        37,
        39,
        41,
        51,
        52,
    }
    actual_instr_indexes = {loc.loc.instr_index for loc in sliced_data}

    assert len(sliced_data) == len(
        expected_instr_indexes
    ), f"Expected {len(expected_instr_indexes)} tainted locations, got {len(sliced_data)}"
    assert actual_instr_indexes == expected_instr_indexes, (
        f"Expected instruction indexes {sorted(expected_instr_indexes)}, "
        f"got {sorted(actual_instr_indexes)}"
    )

    # Key use/seed/sink checks
    assert any(
        loc.loc.instr_index == 0 for loc in sliced_data
    ), "Missing seed (var_4c = a)"
    assert any(
        loc.loc.instr_index == 41 for loc in sliced_data
    ), "Missing snprintf use site"
    assert any(
        loc.loc.instr_index == 52 for loc in sliced_data
    ), "Missing return instruction"


def test_fwd_slice_var(
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
    #   11 @ 004018ee  rdi_1 = &var_2b
    sliced_data, _, tainted_vars = analysis.tainted_slice(
        target=TaintTarget(0x004018EE, "var_2b"),
        var_type=SlicingID.FunctionVar,
    )

    expected_instr_indexes = {
        11,
        12,
        13,
        14,
        17,
        18,
        19,
        22,
        25,
        26,
        28,
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


def test_complete_fwd_slice_var(
    bg_init,
    test_bin=get_bndb_path_or_original(f"{bingoggles_path}/binaries/bin/test_uaf.bndb"),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        # 00402239        void* buffer = __libc_malloc(0x64)
        target=TaintTarget(0x00402239, "buffer"),
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Forward,
    )

    expected_funcs = {"level_eight", "deeper_and_deeper", "deeper_function", "do_free"}
    actual_funcs = {fn for (fn, _) in data.keys()}
    pprint(actual_funcs)
    pprint(data)

    # Assert expected functions are present
    missing = expected_funcs - actual_funcs
    assert not missing, f"Missing expected functions in taint trace: {sorted(missing)}"


def test_complete_fwd_slice_param(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_is_param_tainted.bndb"
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
        target=TaintTarget(0x00401b53, "b"),
        var_type=SlicingID.FunctionParam,
        slice_type=SliceType.Forward,
    )
    #:TODO implement the proper assertions
    # Validate presence of functions
    # expected_funcs = {"do_calculation_and_write_to_buf", "do_math"}
    # assert expected_funcs.issubset(
    #     {key[0] for key in data}
    # ), f"Expected functions {expected_funcs} not all present in result keys"

    # # Flatten locations and vars
    # all_locs = []
    # all_vars = []
    # for (func, _), (locs, vars_) in data.items():
    #     all_locs.extend(locs)
    #     all_vars.extend(vars_)

    # # Basic propagation check
    # assert len(all_locs) >= 10, f"Expected ≥10 propagation steps, got {len(all_locs)}"

    # # Check that specific variables were tainted
    # expected_var_names = {"b", "eax", "edx", "eax_2", "result", "eax_4"}
    # found_var_names = {str(var.variable) for var in all_vars}
    # assert expected_var_names.issubset(
    #     found_var_names
    # ), f"Expected tainted vars {expected_var_names}, got {found_var_names}"

    pprint(data)


def test_is_param_tainted(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_is_param_tainted.bndb"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    # 00401af0    void* my_strcpy(char* d, char* s)
    data = aux.trace_function_taint(
        function_node="my_strcpy", tainted_params=tuple(["s"]), binary_view=bv
        # function_node="do_calculation_and_write_to_buf", tainted_params=tuple(["b"]), binary_view=bv
    )

    # assert data.is_return_tainted is True

    # Parameter names should include both 'd' and 's'
    # param_names = {v.name for v in data.tainted_param_names}
    # assert "d" in param_names
    # assert "s" in param_names
    # assert len(param_names) == 2

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
        # 0040194b  _IO_fgets(rdi, 0x64, rdx)
        target=TaintTarget(0x0040194B, "rdi"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(tainted_vars)


def test(
    bg_init,
    test_bin=get_bndb_path_or_original(
        f"{bingoggles_path}/binaries/bin/test_interproc_param_tainting.bndb"
    ),
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=[],
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    results = aux.trace_function_taint(
        function_node=0x00401A38, tainted_params=("temp_array"), binary_view=bv
    )

    pprint(results)
