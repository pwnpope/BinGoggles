from os.path import abspath
from pprint import pprint

from bingoggles.vfa import Analysis
from bingoggles.bingoggles_types import *
from bingoggles.modules import *
from bingoggles.graph_builder import build_dataflow_graph


def test_backwards_slice_var(bg_init, test_bin="./test/binaries/bin/test_mlil_store"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    tainted_locs, func_name, tainted_params = analysis.tainted_slice(
        target=TaintTarget(0x0040123D, "rsi"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Backward,
    )
    assert len(tainted_locs) > 0, "No tainted locations found"
    assert (
        len(tainted_locs) == 12
    ), f"Expected 12 tainted locations, but got {len(tainted_locs)}"


def test_backwards_slice_param(
    bg_init, test_bin="./test/binaries/bin/test_backwards_slice"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    tainted_locs, func_name, tainted_params = analysis.tainted_slice(
        target=TaintTarget(0x0040123D, "rsi"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionParam,
    )
    assert len(tainted_locs) > 0, "No tainted locations found"
    assert (
        len(tainted_locs) == 1
    ), f"Expected 1 tainted location, but got {len(tainted_locs)}"


def test_fwd_slice_param(bg_init, test_bin="./test/binaries/bin/test_slices"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    sliced_data, _, _ = analysis.tainted_slice(
        target=TaintTarget(0x00401249, "a"),
        var_type=SlicingID.FunctionParam,
        output=OutputMode.Returned,
    )

    assert len(sliced_data) > 0, "No tainted locations found"
    assert (
        len(sliced_data) == 13
    ), f"Expected 13 tainted locations, but got {len(sliced_data)}"


def test_fwd_slice_var(bg_init, test_bin="./test/binaries/bin/test_mlil_store"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    sliced_data, _, tainted_vars = analysis.tainted_slice(
        #   11 @ 00401212  rdi = &buf
        target=TaintTarget(0x00401212, "rdi"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(sliced_data)
    pprint(tainted_vars)
    instr_index_sequence = [11, 12, 17, 18, 19, 22, 25, 26, 28]

    for tainted in sliced_data:
        expr_id = tainted.loc.instr_index
        expected_instr_index = instr_index_sequence.pop(0)
        assert (
            expr_id == expected_instr_index
        ), f"Expected {expected_instr_index}, but got {expr_id} at index {tainted.loc.instr_index}"


def test_get_sliced_calls(
    bg_init, test_bin="./test/binaries/bin/test_get_sliced_calls"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    sliced_data, func_name, propagated_variables = analysis.tainted_slice(
        target=TaintTarget(0x004011DC, "a"),
        var_type=SlicingID.FunctionVar,
    )

    result = analysis.get_sliced_calls(sliced_data, func_name, propagated_variables)

    assert len(result) == 3

    names = {info[0] for info in result.values()}
    assert names == {"__isoc99_scanf", "do_add", "printf"}

    param_maps = {info[0]: info[3] for info in result.values()}

    scanf_map = param_maps["__isoc99_scanf"]
    assert len(scanf_map) == 1
    scanf_param, scanf_counts = next(iter(scanf_map.items()))
    assert isinstance(scanf_param, MediumLevelILVar)
    assert str(scanf_param) == "rsi"
    assert scanf_counts == (2, 2)

    add_map = param_maps["do_add"]
    assert len(add_map) == 1
    add_param, add_counts = next(iter(add_map.items()))
    assert isinstance(add_param, MediumLevelILVar)
    assert str(add_param) == "rdi"
    assert add_counts == (4, 1)

    printf_map = param_maps["printf"]
    assert len(printf_map) == 1
    printf_param, printf_counts = next(iter(printf_map.items()))
    assert isinstance(printf_param, MediumLevelILVar)
    assert str(printf_param).startswith("rsi")
    assert printf_counts == (8, 2)

    pprint(result)


def test_complete_bkd_slice_var(
    bg_init, test_bin="./test/binaries/bin/test_backwards_slice"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        #    7 @ 00401456  foo(a: rdi, b: rsi)
        target=TaintTarget(0x00401456, "rsi"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Backward,
    )

    assert ("main",) in [key[:1] for key in data]
    assert ("foo",) in [key[:1] for key in data]

    main_entry = [entry for entry in data if entry[0] == "main"][0]
    foo_entry = [entry for entry in data if entry[0] == "foo"][0]

    assert "rsi" in str(main_entry[1])
    assert "b" in str(foo_entry[1])

    main_trace, _ = data[main_entry]
    foo_trace, _ = data[foo_entry]

    main_instr_indexes = [entry.loc.instr_index for entry in main_trace]
    assert set(main_instr_indexes) >= {4, 5, 7}, "Missing expected instrs in main"

    foo_instr_indexes = [entry.loc.instr_index for entry in foo_trace]
    assert set(foo_instr_indexes) >= {1, 4, 8}, "Missing expected instrs in foo"

    assert any("b" in str(entry.propagated_var) for entry in foo_trace)

    pprint(data)


def test_complete_fwd_slice_var(bg_init, test_bin="./test/binaries/bin/test_uaf"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        target=TaintTarget(0x00401A5C, "rdi_2"),
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Forward,
    )

    expected_funcs = {"level_eight", "deeper_and_deeper", "deeper_function", "do_free"}
    actual_funcs = {fn for (fn, _) in data.keys()}
    for fn in expected_funcs:
        assert fn in actual_funcs, f"Expected function '{fn}' in taint trace"

    expected_instrs = {
        "level_eight": {14, 15},
        "deeper_and_deeper": {0, 2, 3, 4},
        "deeper_function": {0, 2, 3, 4},
        "do_free": {0, 2, 3, 4},
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
    bg_init, test_bin="./test/binaries/bin/test_is_param_tainted"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    # 004013b7    int64_t do_calculation_and_write_to_buf(int a, int b, int c, int d, void* result_name)
    data = analysis.complete_slice(
        target=TaintTarget(0x004013B7, "b"),
        var_type=SlicingID.FunctionParam,
    )

    pprint(data)

    (func_name, var), (locs, vars_propagated) = next(iter(data.items()))

    assert func_name == "do_calculation_and_write_to_buf"
    assert hasattr(var, "name") and var.name == "b"

    # Ensure there are multiple propagation steps and tainted variables
    assert len(locs) >= 20, f"Expected at least 20 propagation steps, got {len(locs)}"
    assert any(
        "sum" in str(v) for v in vars_propagated
    ), "Missing 'sum' in tainted variables"
    assert any(
        "just_for_fun" in str(v) for v in vars_propagated
    ), "Missing 'just_for_fun' in tainted variables"

    # Confirm the original param is still marked tainted
    assert any(
        v.variable.name == "b" for v in vars_propagated
    ), "'b' not found in propagated variables"


def test_is_param_tainted(
    bg_init, test_bin="./test/binaries/bin/test_is_param_tainted"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = aux.is_function_param_tainted(
        # 00401354    void* my_strcpy(char* d, char* s)
        function_node=0x00401354,
        tainted_params=["d"],
    )

    assert data.is_return_tainted is True

    # Parameter names should include both 'd' and 's'
    param_names = {v.name for v in data.tainted_param_names}
    assert "d" in param_names
    assert "s" in param_names
    assert len(param_names) == 2

    # Original tainted param is 'd'
    assert data.original_tainted_variables == ["d"]

    # Taint map should show that 'd' leads to 's'
    taint_map_keys = [v.name for v in data.tainted_param_map.keys()]
    assert "d" in taint_map_keys
    assert sorted(
        [v.name for v in data.tainted_param_map[next(iter(data.tainted_param_map))]]
    ) == ["s"]

    print(data)


def test_global_tracking_fwd_var(
    bg_init, test_bin="./test/binaries/bin/test_global_tracking"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()
    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    # Expected slice for global variable 'glob_buf'
    locs, _, tainted_vars = aux.tainted_slice(
        target=TaintTarget(0x0040131F, "glob_buf"),
        var_type=SlicingID.GlobalVar,
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


def test_uaf(bg_init, test_bin="./test/binaries/bin/test_uaf"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    test_case = input("Which UAF test case would you like to run? (1-8): ")

    match test_case:
        case "1":
            # Testing a basic Use-After-Free (UAF) where memory is allocated, freed, and then accessed.
            # (VULNERABLE):     0 @ 0x0040125a  buf = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x0040125A, "buf"),
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

        case "2":
            # Testing a UAF using realloc with size 0 (effectively freeing the memory), then accessing the freed memory.
            # (VULNERABLE):     0 @ 0x00401308  rax = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x00401308, "rax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )

            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 7
            ), "Expected 7 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "3":
            # No vulnerability, testing for safe usage of allocated memory without freeing it prematurely.
            # (SAFE):           0 @ 0x004013c7  buf = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x004013C7, "buf"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            assert isinstance(vulns, VulnReport), "Expected None, but got a VulnReport"

            print(f"[{Fore.GREEN}SAFE{Fore.GREEN}]: No UAF detected.")

        case "4":
            # Testing UAF where memory is freed and then accessed across function boundaries.
            # (VULNERABLE):     0 @ 0x004014e5  buf = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x004014E5, "buf"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 8
            ), "Expected 8 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "5":
            # Demonstrating UAF where a buffer is freed in one function and then accessed in another function.
            # (VULNERABLE):     0 @ 0x004015ec  rax = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x004015EC, "rax"),
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

        case "6":
            # UAF where memory is reallocated but used after being freed by realloc.
            # (VULNERABLE):     3 @ 0x004016cc  rax_2 = malloc(bytes: 0x64) [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x004016CC, "rax_2"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()
            vuln_reports = [i for i in vulns]

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 13
            ), "Expected 13 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])

        case "7":
            # Safe usage of memory where allocated memory is correctly freed and reallocated.
            # (SAFE):           0 @ 0x00401811  buf = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x00401811, "buf"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()

            assert vulns is None, f"Expected None, but got {type(vulns).__name__}"

            print(f"[{Fore.GREEN}SAFE{Fore.RESET}]: No UAF detected.")

        case "8":
            # Deep sub-function frees buffer and then reuses the memory in the parent function
            # (VULNERBLE):      0 @ 0x004019ed  rax = malloc(bytes: 0x64)   [PASS]
            data = aux.complete_slice(
                target=TaintTarget(0x004019ED, "rax"),
                var_type=SlicingID.FunctionVar,
                slice_type=SliceType.Forward,
            )
            scanners = UseAfterFreeDetection(bv, data)
            vulns = scanners.analyzer()

            assert len(vuln_reports) > 0, "No UAF detected"
            assert len(vuln_reports) == 1, "Multiple UAF detected"
            assert (
                len(vuln_reports[0].vulnerable_path_data) == 13
            ), "Expected 13 elements in the report"

            print(f"[{Fore.GREEN}UAF Detected{Fore.RESET}]:")
            pprint([loc for loc in vuln_reports[0].vulnerable_path_data])


def test_load_struct(bg_init, test_bin="./test/binaries/bin/test_struct_member"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    #   4 @ 0040122a  rax_1->ptr = rdx
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    locs, _, tainted_vars = aux.tainted_slice(
        target=TaintTarget(0x00401231, "ptr"),
        var_type=SlicingID.StructMember,
    )
    expected_instr_indexes = [
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        18,
        19,
        20,
        21,
        22,
        26,
        27,
        29,
        32,
        33,
        34,
        35,
        36,
        38,
        39,
        40,
        41,
        44,
        45,
        46,
        48,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
    ]

    actual_instr_indexes = [loc.loc.instr_index for loc in locs]

    for expected_index in expected_instr_indexes:
        assert (
            expected_index in actual_instr_indexes
        ), f"Expected instruction index {expected_index} not found in slice"


def test_set_var_field(bg_init, test_bin="./test/binaries/bin/test_struct_member"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    locs, _, tainted_vars = aux.tainted_slice(
        target=TaintTarget(0x004013C3, "ptr"),
        var_type=SlicingID.StructMember,
    )

    instr_indexes = [loc.loc.instr_index for loc in locs]

    expected_indexes = {5, 10, 11, 13, 14, 16, 18, 19, 20, 22, 23, 24}
    missing = expected_indexes - set(instr_indexes)
    assert not missing, f"Missing expected instruction indexes: {sorted(missing)}"

    hlil_field_refs = {
        str(loc.loc.hlil) if hasattr(loc.loc, "hlil") else str(loc.loc) for loc in locs
    }

    for field in ["valueCopy", "dblPtr", "str"]:
        assert any(
            field in ref for ref in hlil_field_refs
        ), f"{field} not referenced in HLIL locs"

    sink_instrs = {13, 18, 22, 24}
    for idx in sink_instrs:
        assert idx in instr_indexes, f"Taint did not reach sink at instruction {idx}"


def test_vfg(bg_init, test_bin="./test/binaries/bin/test_struct_member"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()
    aux = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)

    # Trace forward from `ptr` in myStruct
    locs, _, tainted_vars = aux.tainted_slice(
        target=TaintTarget(0x00401231, "ptr"),
        var_type=SlicingID.FunctionVar,
    )

    # Build dataflow graph
    dfg = build_dataflow_graph(locs)
    # Assert we collected taint propagation
    assert len(locs) > 5, f"Expected more than 5 tainted locations, got {len(locs)}"
    assert (
        len(tainted_vars) > 5
    ), f"Expected more than 5 tainted vars, got {len(tainted_vars)}"
    assert len(dfg.edges) > 0, "Expected at least one edge in the dataflow graph"

    # Assert key propagation happened
    node_labels = [str(getattr(n.variable, "member", n.variable)) for n in dfg.nodes]

    assert any("valueCopy" in v for v in node_labels), "valueCopy taint not propagated"
    assert any("dblPtr" in v for v in node_labels), "dblPtr taint not propagated"

    print("\n=== DataflowGraph Nodes ===")
    pprint(sorted(dfg.nodes, key=lambda n: n.addr))

    print("\n=== DataflowGraph Edges ===")
    pprint(sorted(dfg.edges, key=lambda e: (e.source.addr, e.target.addr)))

    print(
        "[PASS] test_vfg: dataflow graph constructed with expected taint propagation."
    )
