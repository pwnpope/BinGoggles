from os.path import abspath
from pprint import pprint

from bingoggles.vfa import Analysis
from bingoggles.bingoggles_types import *
from bingoggles.scanners import *


def test_backwards_slice_var(bg_init, test_bin="./test/binaries/bin/test_mlil_store"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    output = analysis.tainted_backwards_slice(
        target=TaintTarget(0x0040123D, "rsi"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionVar,
    )

    assert True


def test_backwards_slice_param(
    bg_init, test_bin="./test/binaries/bin/test_backwards_slice"
):
    bg = bg_init(
        target_bin=abspath(test_bin), libraries=[], host="127.0.0.1", port=18812
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    analysis.tainted_backwards_slice(
        target=TaintTarget(0x000011C9, "buf_two"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionParam,
    )


def test_fwd_slice_param(bg_init, test_bin="./test/binaries/bin/test_slices"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    sliced_data, _, _ = analysis.tainted_forward_slice(
        target=TaintTarget(0x00401249, "a"),
        var_type=SlicingID.FunctionParam,
        output=OutputMode.Returned,
    )

    assert True


def test_fwd_slice_var(bg_init, test_bin="./test/binaries/bin/test_mlil_store"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)
    sliced_data, _, tainted_vars = analysis.tainted_forward_slice(
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

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    sliced_data, func_name, propagated_variables = analysis.tainted_forward_slice(
        target=TaintTarget(0x004011DC, "a"),
        var_type=SlicingID.FunctionVar,
    )

    print(analysis.get_sliced_calls(sliced_data, func_name, propagated_variables))

    assert True


def test_complete_bkd_slice_var(
    bg_init, test_bin="./test/binaries/bin/test_backwards_slice"
):
    bg = bg_init(
        target_bin=abspath(test_bin), libraries=[], host="127.0.0.1", port=18812
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        target=TaintTarget(0x00001381, "rsi_4"),
        output=OutputMode.Returned,
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Backward,
    )

    assert True


def test_complete_fwd_slice_var(
    bg_init, test_bin="/home/pope/BitXCHG/CR-team/home/t1.bndb"
):
    bg = bg_init(
        target_bin=abspath(test_bin), libraries=["/lib/x86_64-linux-gnu/libc.so.6"]
    )
    bv, libraries_mapped = bg.init()

    #    7 @ 00012c20  data = input_buffer
    #   00013f60  r0_16 = recv(__fd: r0_15, __buf: &DATABUF, __n: &__elf_header, __flags: r3_4)
    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        target=TaintTarget(0x00013F60, "DATABUF"),
        var_type=SlicingID.FunctionVar,
        slice_type=SliceType.Forward,
    )

    assert True


def test_complete_fwd_slice_param(
    bg_init, test_bin="./test/binaries/bin/test_is_param_tainted"
):
    bg = bg_init(
        target_bin=abspath(test_bin), libraries=[], host="127.0.0.1", port=18812
    )
    bv, libraries_mapped = bg.init()

    analysis = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = analysis.complete_slice(
        target=TaintTarget(0x00001255, "b"),
        var_type=SlicingID.FunctionParam,
        slice_type=SliceType.Forward,
    )

    pprint(data)

    assert True


def test_is_param_tainted(
    bg_init, test_bin="./test/binaries/bin/test_interproc_param_tainting"
):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    data = aux.is_function_param_tainted(function_node=0x0040133c, tainted_params=["final_array"]) 
                                         #tainted_params=["final_array", "temp_array", "size", "start_val", "shift", "adjust_val"])

    print(data)
    assert True


def test_load_libs(bg_init, test_bin="./test/binaries/bin/test_slices_new"):
    # If no cache is found, perform the processing
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()
    print(bv, libraries_mapped)

    return True


def test_fmt_str_detection(bg_init, test_bin="./test/binaries/bin/test_slices_new"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    locs, _, tainted_vars = aux.tainted_forward_slice(
        target=TaintTarget(0x00401241, "rsi"),
        var_type=SlicingID.FunctionVar,
    )

    assert True


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
    #   10 @ 0040131f  strcpy(&glob_buf, rsi)
    #   278 @ 00417ab8  get_media_info(r0_19, 1, &data_1744b5c)
    locs, _, tainted_vars = aux.tainted_forward_slice(
        target=TaintTarget(0x0040131F, "glob_buf"),
        var_type=SlicingID.FunctionVar,
    )

    assert True


def test_uaf(bg_init, test_bin="./test/binaries/bin/test_uaf"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    """
        # Level One: Testing a basic Use-After-Free (UAF) where memory is allocated, freed, and then accessed.
        Level One:   (VULNERABLE):     0 @ 0x0040125a  buf = malloc(bytes: 0x64)   [PASS]

        # Level Two: Testing a UAF using realloc with size 0 (effectively freeing the memory), then accessing the freed memory.
        Level Two:   (VULNERABLE):     0 @ 0x00401308  rax = malloc(bytes: 0x64)   [PASS]

        # Level Three: No vulnerability, testing for safe usage of allocated memory without freeing it prematurely.
        Level Three: (SAFE):           0 @ 0x004013c7  buf = malloc(bytes: 0x64)   [PASS]

        # Level Four: Testing UAF detection when the vulnerable ptr is reassigned to another.
        Level Four:  (VULNERABLE):     0 @ 0x004014e5  buf = malloc(bytes: 0x64)   [PASS]

        # Level Five: UAF where memory is reallocated but used after being freed by realloc.
        Level Five    (VULNERABLE):     3 @ 0x004016cc  rax_2 = malloc(bytes: 0x64) [PASS]

        # Level Six: Safe usage of memory where allocated memory is correctly freed and reallocated.
        Level Six  (SAFE):           0 @ 0x00401811  buf = malloc(bytes: 0x64)   [PASS]
    """

    aux = Analysis(binaryview=bv, verbose=False, libraries_mapped=libraries_mapped)

    locs, _, tainted_vars = aux.tainted_forward_slice(
        target=TaintTarget(0x004014E5, "buf"),
        var_type=SlicingID.FunctionVar,
    )

    scanners = VulnerabilityScanners(bv, locs, tainted_vars)
    data = scanners.use_after_free()
    pprint(data)

    assert True


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
    locs, _, tainted_vars = aux.tainted_forward_slice(
        target=TaintTarget(0x00401231, "ptr"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(tainted_vars)
    assert True


def test_set_var_field(bg_init, test_bin="./test/binaries/bin/test_struct_member"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)

    locs, _, tainted_vars = aux.tainted_forward_slice(
        target=TaintTarget(0x004013C3, "ptr"),
        var_type=SlicingID.FunctionVar,
    )

    pprint(tainted_vars)
    assert True


def test_vfg_generation(bg_init, test_bin="./test/binaries/bin/test_vfg_gen"):
    bg = bg_init(
        target_bin=abspath(test_bin),
        libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
        host="127.0.0.1",
        port=18812,
    )
    bv, libraries_mapped = bg.init()

    aux = Analysis(binaryview=bv, verbose=True, libraries_mapped=libraries_mapped)
    interproc_data = aux.complete_slice(
        #   004011fa    int64_t layered(int input)
        target=TaintTarget(0x004011FA, "input"),
        var_type=SlicingID.FunctionParam,
        slice_type=SliceType.Forward,
    )

    pprint(interproc_data)
    assert True
