from bingoggles_types import *
from binaryninja.enums import MediumLevelILOperation
from binaryninja.mediumlevelil import MediumLevelILVar


class VulnerabilityScanners:
    def __init__(self, bv, lines_of_code_gathered, tainted_variables) -> None:
        self.bv = bv
        self.lines_of_code_gathered = lines_of_code_gathered
        self.tainted_variables = tainted_variables

    def use_after_free(
        self,
        alloc_functions=["malloc", "new", "realloc"],
        dealloc_functions=["free", "delete", "realloc"],
    ):
        """
        Detects potential use-after-free (UAF) vulnerabilities in the analyzed code.

        Args:
            alloc_functions (list): List of memory allocation function names to monitor.
            dealloc_functions (list): List of memory deallocation function names to monitor.

        Returns:
            dict: A dictionary where keys are vulnerability identifiers and values are lists of
                code locations indicating potential UAF vulnerabilities.

        :TODO
            - Implement the interprocederal analysis
        """
        use_after_frees_detected = {}
        count = 1
        tainted_vars = [t_var.variable for t_var in self.tainted_variables]

        def get_last_buffer_allocated(path_data):
            for tainted_loc in path_data:
                if int(tainted_loc.loc.operation) == int(
                    MediumLevelILOperation.MLIL_CALL
                ):
                    func = self.bv.get_functions_containing(
                        int(str(tainted_loc.loc.dest), 16)
                    )[0]
                    if func.name in alloc_functions:
                        # Treat realloc differently
                        if func.name == "realloc" and not detect_realloc_free(
                            func, tainted_loc
                        ):
                            return tainted_loc

                        return tainted_loc

        def is_buffer_reallocated_after_free(path_data, dealloc_loc) -> bool:
            """
            Determines if a buffer has been reallocated after deallocation with the same size
            or a user-controlled size.

            Args:
                path_data (list): List of code locations representing the execution path.
                dealloc_loc (Location): The location where the buffer was deallocated.

            Returns:
                bool: True if the buffer is reallocated appropriately; False otherwise.
            """
            alloc_func = get_last_buffer_allocated(path_data)
            func_object = tainted_loc.loc.function

            for block in func_object.source_function.medium_level_il:
                for loc in block:
                    if loc.address >= dealloc_loc.loc.address and int(
                        loc.operation
                    ) == int(MediumLevelILOperation.MLIL_CALL):
                        func = self.bv.get_functions_containing(int(str(loc.dest), 16))[
                            0
                        ]
                        if func.name in alloc_functions:
                            call_params = loc.params

                            if func.name == "realloc":
                                size = call_params[1]

                                # This assumes the user can control the size of the realloc meaning the user can realloc with size zero
                                if size in tainted_vars:
                                    return False

                                elif int(size.value) == int(
                                    alloc_func.loc.params[0].value
                                ):
                                    return True

                            else:
                                size = call_params[0]

                                # This assumes the user can control the size of the realloc meaning the user can realloc with size zero
                                if (
                                    isinstance(size, MediumLevelILVar)
                                    and size in tainted_vars
                                ):
                                    return False

                                elif int(size.value) == int(
                                    alloc_func.loc.params[0].value
                                ):
                                    return True

            return False

        def returns_after_being_freed(path_data, dealloc_loc: TaintedLOC):
            """
            Determines if the function returns or jumps immediately after a buffer is freed.

            Args:
                path_data (list): List of code locations representing the execution path.
                dealloc_loc (Location): The location where the buffer was deallocated.

            Returns:
                bool: True if the function returns or jumps immediately after deallocation; False otherwise.
            """
            function_object = dealloc_loc.function_object
            path_data_addresses = [t_loc.loc.address for t_loc in path_data]

            for block in function_object.medium_level_il:
                for loc in block:
                    # Check for return after deallocation
                    if (
                        loc.address > dealloc_loc.loc.address
                        and int(loc.operation) == int(MediumLevelILOperation.MLIL_RET)
                        and all(
                            loc.address < address for address in path_data_addresses
                        )
                    ):
                        return True

                    # Check for jump to return after deallocation
                    elif loc.instr_index > dealloc_loc.loc.instr_index and int(
                        loc.operation
                    ) == int(MediumLevelILOperation.MLIL_GOTO):
                        # Check if the jump destination is a return instruction
                        jump_instr_index = int(str(loc.dest), 10)
                        if jump_instr_index:
                            jump_target = function_object.get_llil_at(
                                function_object.mlil[jump_instr_index].address
                            ).mlil
                            if (
                                jump_target
                                and int(jump_target.operation)
                                == int(MediumLevelILOperation.MLIL_RET)
                                and all(
                                    loc.address < address
                                    for address in path_data_addresses
                                )
                            ):
                                return True

            return False

        def function_frees_buffer(tainted_loc, lines_of_code_gathered: list) -> bool:
            if int(tainted_loc.loc.operation) == int(MediumLevelILOperation.MLIL_CALL):
                func_obj = self.bv.get_functions_containing(
                    int(str(tainted_loc.loc.dest), 16)
                )[0]
                if func_obj.name in dealloc_functions:

                    if is_buffer_reallocated_after_free(
                        lines_of_code_gathered, tainted_loc
                    ):
                        return False

                    else:
                        return True

            return False

        def detect_uaf(path_data, dealloc_loc: TaintedLOC) -> list:
            """
            Identifies the sequence of code locations that lead to a potential use-after-free
            vulnerability after a deallocation.

            Args:
                path_data (list): List of code locations representing the execution path.
                dealloc_loc (Location): The location where the buffer was deallocated.

            Returns:
                list: A list of code locations indicating the vulnerable path, or an empty list
                    if no vulnerability is detected.
            """
            vulnerable_path = []

            if is_buffer_reallocated_after_free(path_data, dealloc_loc):
                return []

            if returns_after_being_freed(path_data, dealloc_loc):
                return []

            for t_loc in path_data:
                # if dealloc_loc.loc.address > t_loc.loc.address:
                #     continue
                if t_loc.loc.address > dealloc_loc.loc.address:
                    if any(var in tainted_vars for var in t_loc.loc.vars_read) or any(
                        var in tainted_vars for var in t_loc.loc.vars_written
                    ):
                        vulnerable_path.append(t_loc)

            return vulnerable_path

        def detect_realloc_free(alloc_func, tainted_loc):
            """
            Checks if a reallocation function call can lead to a deallocation when the size
            parameter is zero or user-controlled.

            Args:
                alloc_func (Function): The allocation function being analyzed.
                tainted_loc (Location): The location of the function call with potential taint.

            Returns:
                bool: True if the reallocation can result in deallocation; False otherwise.
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

        for tainted_loc in self.lines_of_code_gathered:
            if int(tainted_loc.loc.operation) == int(MediumLevelILOperation.MLIL_CALL):
                func = self.bv.get_functions_containing(
                    int(str(tainted_loc.loc.dest), 16)
                )[0]

                # Tracing the paths for post dealloction functions
                if (
                    func.name in dealloc_functions
                    or detect_realloc_free(func, tainted_loc)
                    or function_frees_buffer(tainted_loc, self.lines_of_code_gathered)
                ):
                    vuln_path = detect_uaf(self.lines_of_code_gathered, tainted_loc)
                    if len(vuln_path) > 0:
                        use_after_frees_detected[count] = vuln_path
                        count += 1

        return use_after_frees_detected
