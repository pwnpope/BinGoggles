from binaryninja.enums import MediumLevelILOperation
from binaryninja.mediumlevelil import MediumLevelILVar
from binaryninja.enums import MediumLevelILOperation
from binaryninja.mediumlevelil import MediumLevelILVar

from bingoggles.auxiliary import func_name_to_object
from bingoggles.bingoggles_types import *

class UseAfterFreeDetection:
    def __init__(self, bv, slice_data: dict):
        """
        Args:
            bv (BinaryView): The Binary Ninja view object.
            slice_data (dict): Output from complete_slice().
                               Format: { (func_name, variable): (list[TaintedLOC], list[TaintedVar]) }
        """
        self.bv = bv
        self.slice_data = slice_data
        self.alloc_functions = ["malloc", "new", "realloc", "calloc"]
        self.dealloc_functions = ["free", "delete", "realloc"]
        self.combined_tainted_vars_path = [
            var.variable
            for _, (path_data, tainted_vars) in self.slice_data.items()
            for var in tainted_vars
        ]

    def _flatten_path_data(self):
        flattened = []
        for _, (locs, _) in self.slice_data.items():
            flattened.extend(locs)
        return sorted(flattened, key=lambda x: x.addr)

    def analyzer(self, parent_function_name=None) -> VulnReport | None:
        """
        Detects use-after-free vulnerabilities, including across function boundaries.

        Returns:
            dict: { vuln_id: [TaintedLOC, ...] } for each detected UAF path.
        """

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
                if int(t_loc.loc.operation) != int(MediumLevelILOperation.MLIL_CALL):
                    continue

                try:
                    func_obj = self.bv.get_functions_containing(
                        int(str(t_loc.loc.dest), 16)
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
        Interprocedural function to check if a function calls a deallocation function.
        This is used to identify if a function may free a buffer that is tainted.
        """
        fn = func_name_to_object(self, func_name)
        if not fn:
            return False

        for block in fn.medium_level_il:
            for loc in block:
                if int(loc.operation) != int(MediumLevelILOperation.MLIL_CALL):
                    continue

                try:
                    subfn = self.bv.get_functions_containing(int(str(loc.dest), 16))[0]
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
        Identifies UAF usage after a deallocation, unless buffer is reallocated or the function returns.

        Returns:
            list of TaintedLOC if a vulnerable use is found, else []
        """
        vulnerable_path = []
        path_data = sorted(path_data, key=lambda t: t.addr)
        tainted_names = {v.name for v in tainted_vars}

        if self._is_buffer_reallocated_after_free(path_data, dealloc_loc, tainted_vars):
            #:DEBUG
            print(dealloc_loc, "[+] Buffer reallocated after free")
            return []

        if dealloc_loc.function_object.name == parent_function_name:
            if self._returns_after_being_freed(path_data, dealloc_loc):
                #:DEBUG
                print(dealloc_loc, "[+] Function returns after being freed")
                return []

        dealloc_addr = dealloc_loc.addr
        dealloc_func = dealloc_loc.function_object.name

        for (_, _), (cross_path_data, _) in self.slice_data.items():
            for t_loc in cross_path_data:
                if (
                    t_loc.addr > dealloc_addr
                    and t_loc.function_object.name == dealloc_func
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
        Checks if a buffer was reallocated after a free (interprocedurally).
        Avoids infinite recursion by keeping track of visited functions.
        """
        if visited_functions is None:
            visited_functions = set()

        alloc_func = self._get_last_buffer_allocated(path_data, tainted_vars)
        func_object = dealloc_loc.function_object

        # Recursively checks if any function called within this function reallocates the buffer
        def check_allocations_in_function(func_object, dealloc_loc, alloc_func):
            for block in func_object.medium_level_il:
                for loc in block:
                    if loc.address >= dealloc_loc.loc.address and int(
                        loc.operation
                    ) == int(MediumLevelILOperation.MLIL_CALL):
                        try:
                            func = self.bv.get_functions_containing(
                                int(str(loc.dest), 16)
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
                        if func.name != dealloc_loc.function_object.name:
                            if self._is_buffer_reallocated_after_free(
                                path_data, dealloc_loc, tainted_vars, visited_functions
                            ):
                                return True

            return False

        # Start checking from the current function
        return check_allocations_in_function(func_object, dealloc_loc, alloc_func)

    def _returns_after_being_freed(self, path_data, dealloc_loc: TaintedLOC):
        """
        Returns True *only* if the function returns or jumps to return
        without any *in-function* tainted LOCs in between.
        """
        fn = dealloc_loc.function_object
        dealloc_addr = dealloc_loc.addr
        rets_after_free = False

        for block in fn.medium_level_il:
            for loc in block:
                if loc.address <= dealloc_addr:
                    continue

                # Case 1: Direct return
                if int(loc.operation) == int(MediumLevelILOperation.MLIL_RET):
                    if any(
                        dealloc_addr < tl.addr < loc.address
                        and tl.function_object == fn
                        for tl in path_data
                    ):
                        rets_after_free = False
                    else:
                        rets_after_free = True

                # Case 2: Goto that jumps to return
                if int(loc.operation) == int(MediumLevelILOperation.MLIL_GOTO):
                    jump_instr_index = int(str(loc.dest), 10)
                    try:
                        jump_target = fn.get_llil_at(
                            fn.mlil[jump_instr_index].address
                        ).mlil
                    except IndexError:
                        continue

                    if jump_target and int(jump_target.operation) == int(
                        MediumLevelILOperation.MLIL_RET
                    ):
                        if any(
                            dealloc_addr < tl.addr < loc.address
                            and tl.function_object == fn
                            for tl in path_data
                        ):
                            rets_after_free = False
                        else:

                            rets_after_free = True

        return rets_after_free

    def _get_last_buffer_allocated(self, path_data, tainted_vars) -> TaintedLOC | None:
        """
        Finds the last allocation call in the path data.
        """
        for tainted_loc in path_data:
            if int(tainted_loc.loc.operation) == int(MediumLevelILOperation.MLIL_CALL):
                try:
                    func = self.bv.get_functions_containing(
                        int(str(tainted_loc.loc.dest), 16)
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
        Returns True if realloc is acting as a deallocation.
        """
        if alloc_func.name == "realloc":
            call_params = tainted_loc.loc.params
            size = call_params[1]

            if isinstance(size, MediumLevelILVar) and size in tainted_vars:
                return True
            elif (
                int(size.operation) == int(MediumLevelILOperation.MLIL_CONST)
                and int(size.value) == 0
            ):
                return True

        return False
