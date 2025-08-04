from binaryninja.enums import MediumLevelILOperation
from binaryninja.mediumlevelil import MediumLevelILVar, MediumLevelILConst
from binaryninja import BinaryView
from bingoggles.auxiliary import func_name_to_object
from bingoggles.bingoggles_types import *
from typing import Union


class UseAfterFreeDetection:
    def __init__(self, bv: BinaryView, slice_data: dict = None):
        """
        Detect use-after-free (UAF) vulnerabilities through interprocedural taint analysis.

        This class performs UAF detection by analyzing tainted slices across function boundaries.
        It identifies memory deallocations (e.g., `free`, `delete`, `realloc`) and checks whether
        any subsequent usage of the freed buffer occurs without proper reallocation or early function
        termination.

        Attributes:
            bv (BinaryView): The Binary Ninja view object for the binary being analyzed.
            slice_data (dict): The result of `complete_slice()` analysis, mapping function-variable pairs
                            to tainted paths and propagated variables.
            alloc_functions (List[str]): Names of functions considered allocation sources.
            dealloc_functions (List[str]): Names of functions considered deallocation sinks.
            combined_tainted_vars_path (List[Variable]): Flattened list of tainted variables from all slices.

        Methods:
            analyzer(parent_function_name=None) -> VulnReport | None:
                Runs the main UAF detection logic across all tainted paths.

            _calls_function_that_frees(func_name) -> bool:
                Recursively checks if the given function (or any it calls) invokes a known deallocation.

            _detect_uaf(parent_function_name, path_data, dealloc_loc, tainted_vars) -> list:
                Determines whether any use of tainted variables occurs after a free call.

            _is_buffer_reallocated_after_free(path_data, dealloc_loc, tainted_vars, visited_functions=None) -> bool:
                Detects if a previously freed buffer has been safely reallocated afterward.

            _returns_after_being_freed(path_data, dealloc_loc) -> bool:
                Checks whether the function returns immediately after a deallocation, with no further usage.

            _get_last_buffer_allocated(path_data, tainted_vars) -> TaintedLOC | None:
                Finds the most recent allocation site before a detected deallocation.

            _detect_realloc_free(alloc_func, tainted_loc, tainted_vars) -> bool:
                Heuristically detects whether `realloc` is being used to free memory (e.g., size = 0).
        """
        self.bv = bv
        self.slice_data = slice_data
        self.alloc_functions = ["malloc", "new", "realloc", "calloc"]
        self.dealloc_functions = ["free", "delete", "realloc"]
        if self.slice_data:
            self.combined_tainted_vars_path = [
                var.variable
                for _, (path_data, tainted_vars) in self.slice_data.items()
                for var in tainted_vars
            ]

    def _flatten_path_data(self) -> list:
        flattened = []
        for _, (locs, _) in self.slice_data.items():
            flattened.extend(locs)
        return sorted(flattened, key=lambda x: x.addr)

    def analyzer(self, parent_function_name=None) -> Union[VulnReport, None]:
        """
        Analyze sliced data to detect potential Use-After-Free (UAF) vulnerabilities.

        This method iterates through the provided interprocedural taint slice data to
        identify call sites that match known deallocation functions (e.g., `free`, `delete`,
        `realloc`). It then checks for any usage of tainted variables after these calls
        without proper reallocation or early function return, signaling a potential UAF.

        Args:
            parent_function_name (str, optional): Name of the original function being analyzed.
                Used to correlate context when scanning across multiple functions. If None,
                the function name is inferred from the tainted slice.

        Returns:
            VulnReport | None:
                A list of `VulnReport` objects, each representing a detected UAF path.
                Returns None if no vulnerabilities are found.

        Notes:
            - This is the main entry point for UAF detection logic.
            - It uses both direct deallocation calls and recursive interprocedural checks.
            - Each `VulnReport` contains a traceable path of `TaintedLOC` instances indicating
              where a freed variable was subsequently accessed.
        """

        if not self.slice_data:
            raise ValueError(
                "slice_data must be provided in order to run this function"
            )

        use_after_frees_detected = {}
        count = 1

        for (tainted_func_name, tanited_var_or_param), (
            path_data,
            tainted_vars,
        ) in self.slice_data.items():
            t_vars = [t_var.variable for t_var in tainted_vars]
            if not parent_function_name:
                parent_function_name = tainted_func_name

            for t_loc in path_data:
                if t_loc.loc.operation.value != MediumLevelILOperation.MLIL_CALL.value:
                    continue

                try:
                    func_obj = self.bv.get_functions_containing(
                        t_loc.loc.dest.value.value
                    )[0]

                except IndexError:
                    continue

                if func_obj.name in self.dealloc_functions:
                    dealloc_callsite = t_loc

                elif self._calls_function_that_frees(func_obj.name):
                    dealloc_callsite = t_loc

                else:
                    continue

                #:DEBUG
                # print(f"[UAF CHECK] Dealloc callsite addr: {hex(dealloc_callsite.addr)} (calls {func_obj.name})")

                if dealloc_callsite:
                    vuln_path = self._detect_uaf(
                        parent_function_name=parent_function_name,
                        path_data=self._flatten_path_data(),
                        dealloc_loc=dealloc_callsite,
                        tainted_vars=t_vars,
                    )

                    if vuln_path:
                        use_after_frees_detected[count] = vuln_path
                        count += 1

        if len(use_after_frees_detected) > 0:
            vulnerability_reports = []
            for (
                _,
                path,
            ) in use_after_frees_detected.items():
                vulnerability_reports.append(VulnReport(path))

            return vulnerability_reports

        else:
            return None

    def _calls_function_that_frees(self, func_name) -> bool:
        """
        Recursively determine if the given function (or any function it calls) performs a deallocation.

        This method is used to identify whether a function, directly or indirectly, invokes
        a known deallocation routine (e.g., `free`, `delete`, `realloc`) on a variable that has
        been tainted. It inspects the function's call sites and tracks tainted argument usage.

        Args:
            func_name (str): The name of the function to analyze for deallocation behavior.

        Returns:
            bool: True if the function or any callee frees a tainted buffer, False otherwise.

        Notes:
            - Matches parameters against `self.combined_tainted_vars_path` to confirm taint.
            - Updates `self.dealloc_functions` dynamically if new deallocation functions are discovered.
            - Prevents infinite recursion by not re-analyzing the same function name in direct cycles.
        """
        fn = func_name_to_object(self.bv, func_name)
        if not fn:
            return False

        for block in fn.medium_level_il:
            for loc in block:
                if loc.operation.value != MediumLevelILOperation.MLIL_CALL.value:
                    continue

                try:
                    subfn = self.bv.get_functions_containing(loc.dest.value.value)[0]
                except IndexError:
                    continue

                #:DEBUG
                # print("========== TAINTED VARS ==========")
                # pprint(self.combined_tainted_vars_path)

                # print("========== LOC PARAMS ============")
                # pprint(loc.params)

                if subfn.name in self.dealloc_functions:
                    for param in loc.params:
                        if isinstance(param, MediumLevelILVar):
                            param = param.src

                        if param in self.combined_tainted_vars_path:
                            self.dealloc_functions.append(subfn.name)
                            #:DEBUG
                            # print(f"Found a call to {subfn.name} that frees a buffer")
                            return True

                if subfn.name != func_name:
                    if self._calls_function_that_frees(subfn.name):
                        for param in loc.params:
                            if isinstance(param, MediumLevelILVar):
                                param = param.src

                            if param in self.combined_tainted_vars_path:
                                self.dealloc_functions.append(subfn.name)
                                #:DEBUG
                                # print(f"Found a call to {subfn.name} that frees a buffer")
                                return True

        return False

    def _detect_uaf(
        self, parent_function_name, path_data, dealloc_loc: TaintedLOC, tainted_vars
    ) -> list:
        """
        Detects potential use-after-free (UAF) by analyzing usage of tainted variables after a deallocation point.

        This method checks if any tainted variable is read from or written to after it has been freed.
        It avoids false positives by verifying whether the buffer was reallocated or the function returned
        early after the deallocation.

        Args:
            parent_function_name (str): Name of the function being analyzed as the root context.
            path_data (List[TaintedLOC]): Tainted instruction path for the function(s) involved.
            dealloc_loc (TaintedLOC): The location where a deallocation function was called.
            tainted_vars (List[Variable]): The variables marked as tainted up to this point.

        Returns:
            List[TaintedLOC]: A list of instructions that use the freed variable, indicating a UAF.
                              Returns an empty list if no vulnerable use is detected.

        Notes:
            - Checks for in-function usage of the variable after the `free()` call.
            - Skips reporting if the buffer was reallocated or if the function returned immediately.
            - Matches variable names in `vars_read` and `vars_written` fields to detect accesses.
        """
        vulnerable_path = []
        path_data = sorted(path_data, key=lambda t: t.addr)
        tainted_names = {v.name for v in tainted_vars}

        if self._is_buffer_reallocated_after_free(path_data, dealloc_loc, tainted_vars):
            #:DEBUG
            print(dealloc_loc, "[+] Buffer reallocated after free")
            return []

        if dealloc_loc.function_node.name == parent_function_name:
            if self._returns_after_being_freed(path_data, dealloc_loc):
                #:DEBUG
                print(dealloc_loc, "[+] Function returns after being freed")
                return []

        dealloc_addr = dealloc_loc.addr
        dealloc_func = dealloc_loc.function_node.name

        for (_, _), (cross_path_data, _) in self.slice_data.items():
            for t_loc in cross_path_data:
                if (
                    t_loc.addr > dealloc_addr
                    and t_loc.function_node.name == dealloc_func
                ):
                    read_names = {v.name for v in t_loc.loc.vars_read}
                    written_names = {v.name for v in t_loc.loc.vars_written}

                    if tainted_names & (read_names | written_names):
                        vulnerable_path.append(t_loc)

        return vulnerable_path

    def _is_buffer_reallocated_after_free(
        self, path_data, dealloc_loc, tainted_vars, visited_functions=None
    ) -> bool:
        """
        Determines if a buffer is reallocated after being freed, across function boundaries.

        This function helps prevent false positive UAF detections by identifying cases where
        a buffer, once freed, is subsequently reallocated—either in the same function or in
        a function it calls. It avoids infinite recursion by tracking functions already visited.

        Args:
            path_data (List[TaintedLOC]): Taint propagation path containing allocation and deallocation events.
            dealloc_loc (TaintedLOC): The instruction representing the deallocation (e.g., `free()` call).
            tainted_vars (List[Variable]): The list of tainted variables being tracked.
            visited_functions (set[str], optional): Set of function names already visited to prevent infinite recursion.

        Returns:
            bool: True if the buffer is found to be reallocated after the `free()` call, False otherwise.

        Notes:
            - Supports interprocedural analysis: if the current function calls other functions,
              it will recursively check those for reallocations.
            - Special-cases `realloc`: detects whether it's acting as an allocator or deallocator.
            - Compares parameter values to infer equivalence of allocations.
        """

        if visited_functions is None:
            visited_functions = set()

        alloc_func = self._get_last_buffer_allocated(path_data, tainted_vars)
        func_object = dealloc_loc.function_node

        # Recursively checks if any function called within this function reallocates the buffer
        def check_allocations_in_function(func_object, dealloc_loc, alloc_func):
            for block in func_object.medium_level_il:
                for loc in block:
                    if (
                        loc.address >= dealloc_loc.loc.address
                        and int(loc.operation) == MediumLevelILOperation.MLIL_CALL.value
                    ):
                        try:
                            func = self.bv.get_functions_containing(
                                loc.dest.value.value
                            )[0]
                        except IndexError:
                            continue

                        if func.name in visited_functions:
                            continue

                        # Mark this function as visited
                        visited_functions.add(func.name)

                        if func.name in self.alloc_functions:
                            size = (
                                loc.params[1]
                                if func.name == "realloc"
                                else loc.params[0]
                            )
                            #:TODO implement different alloc functions to get their respective size param and see if the size is reallocated
                            # if func.name == "realloc":
                            #     size = loc.params[1]
                            # elif func.name == "malloc" or func.name == "new":
                            #     size = loc.params[0]
                            # elif func.name == "calloc":
                            #     nbytes = loc.params[0]
                            #     element_size = loc.params[1]
                            #     if isinstance(
                            #         nbytes, MediumLevelILConst
                            #     ) and isinstance(element_size, MediumLevelILConst):
                            #         size = nbytes.constant * element_size.constant
                            #     else:
                            #         size = nbytes
                            # else:
                            #     raise NotImplementedError(
                            #         f"Unhandled allocator function: {func.name}"
                            #     )

                            # We're returning false here because we're assuming we're able to influence or control the size
                            # meaning we can make it go into another size range, this is very guessy though.
                            if (
                                isinstance(size, MediumLevelILVar)
                                and size in tainted_vars
                            ):
                                return False

                            if alloc_func and int(size.value) == int(
                                alloc_func.loc.params[0].value
                            ):
                                return True

                        # If the function called isn't the one we're checking, we need to check recursively
                        if func.name != dealloc_loc.function_node.name:
                            if self._is_buffer_reallocated_after_free(
                                path_data, dealloc_loc, tainted_vars, visited_functions
                            ):
                                return True

            return False

        # Start checking from the current function
        return check_allocations_in_function(func_object, dealloc_loc, alloc_func)

    def _returns_after_being_freed(self, path_data, dealloc_loc: TaintedLOC) -> bool:
        """
        Determines if the function returns immediately after a deallocation, without further tainted usage.

        This method checks whether the function either:
        1. Executes a direct return (`MLIL_RET`), or
        2. Jumps to a return via `MLIL_GOTO`

        Args:
            path_data (List[TaintedLOC]): The list of all tainted instructions in the function.
            dealloc_loc (TaintedLOC): The instruction where the deallocation occurred.

        Returns:
            bool: True if the function returns cleanly after the deallocation without using
                  any tainted data. False if any tainted LOC appears between free and return.

        Notes:
            - Avoids false positives in UAF detection by eliminating cases where control flow exits
              safely before a use could occur.
            - Accounts for both direct and indirect (`goto`-based) returns.
        """
        fn = dealloc_loc.function_node
        dealloc_addr = dealloc_loc.addr
        rets_after_free = False

        for block in fn.medium_level_il:
            for loc in block:
                if loc.address <= dealloc_addr:
                    continue

                # Case 1: Direct return
                if loc.operation.value == MediumLevelILOperation.MLIL_RET.value:
                    if any(
                        dealloc_addr < tl.addr < loc.address and tl.function_node == fn
                        for tl in path_data
                    ):
                        rets_after_free = False
                    else:
                        rets_after_free = True

                # Case 2: Goto that jumps to return
                if loc.operation.value == MediumLevelILOperation.MLIL_GOTO.value:
                    jump_instr_index = int(str(loc.dest), 10)
                    try:
                        jump_target = fn.get_llil_at(
                            fn.mlil[jump_instr_index].address
                        ).mlil
                    except IndexError:
                        continue

                    if (
                        jump_target
                        and jump_target.operation.value
                        == MediumLevelILOperation.MLIL_RET.value
                    ):
                        if any(
                            dealloc_addr < tl.addr < loc.address
                            and tl.function_node == fn
                            for tl in path_data
                        ):
                            rets_after_free = False
                        else:

                            rets_after_free = True

        return rets_after_free

    def _get_last_buffer_allocated(self, path_data, tainted_vars) -> TaintedLOC | None:
        """
        Identifies the most recent allocation site in the taint path.

        This method scans the taint path (`path_data`) for calls to known allocation functions
        (e.g., `malloc`, `calloc`, `realloc`) and returns the last such call, if found. It distinguishes
        `realloc` used for freeing (e.g., `realloc(ptr, 0)`) from real reallocations using a helper.

        Args:
            path_data (List[TaintedLOC]): The ordered list of instructions from the taint slice.
            tainted_vars (List[Variable]): The set of variables currently considered tainted.

        Returns:
            TaintedLOC | None: The taint location of the last valid allocation call,
            or None if no allocation is found in the path.

        Notes:
            - `realloc` is only treated as allocation if it's not used to free the buffer.
            - This is used as a prerequisite for checking reallocation after a free.
        """
        for tainted_loc in path_data:
            if (
                tainted_loc.loc.operation.value
                == MediumLevelILOperation.MLIL_CALL.value
            ):
                try:
                    func = self.bv.get_functions_containing(
                        tainted_loc.loc.dest.value.value
                    )[0]
                except IndexError:
                    continue
                if func.name in self.alloc_functions:
                    if func.name == "realloc" and not self._detect_realloc_free(
                        func, tainted_loc, tainted_vars
                    ):
                        return tainted_loc
                    return tainted_loc

        return None

    def _detect_realloc_free(self, alloc_func, tainted_loc, tainted_vars) -> bool:
        """
        Determines whether a `realloc` call is being used to deallocate memory.

        This helper checks the second argument to `realloc()`:
        - If it's a tainted variable, it may represent a dynamic zeroing pattern.
        - If it's a constant zero (`realloc(ptr, 0)`), it's a known idiom for freeing memory.

        Args:
            alloc_func (Function): The Binary Ninja function object for the `realloc` call.
            tainted_loc (TaintedLOC): The tainted instruction where `realloc` was called.
            tainted_vars (List[Variable]): List of tainted variables known at this point.

        Returns:
            bool: True if `realloc` is acting as a deallocation (i.e., size is 0 or tainted),
                  False if it's acting as a normal reallocation.

        Notes:
            - Used to distinguish whether `realloc` should be treated like `free`.
            - Important for determining whether a buffer has been legitimately reallocated.
        """

        if alloc_func.name == "realloc":
            call_params = tainted_loc.loc.params
            size = call_params[1]

            if isinstance(size, MediumLevelILVar) and size in tainted_vars:
                return True

            elif (size, MediumLevelILConst) and int(size.value) == 0:
                return True

            elif (
                size.operation.value == MediumLevelILOperation.MLIL_CONST.value
                and int(size) == 0
            ):
                return True

        return False


class BuildVFG:
    pass
