from dataclasses import dataclass
from binaryninja.variable import Variable
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    SSAVariable,
    MediumLevelILInstruction,
    MediumLevelILLoad,
    MediumLevelILConstPtr,
    MediumLevelILOperation,
)
from binaryninja.types import CoreSymbol
from colorama import Fore
import socket, os, hashlib, pathlib, rpyc, sys
from rich.progress import Progress
from rich.status import Status
from typing import List, Union
from enum import Enum, auto

import binaryninja as bn


class TaintConfidence:
    """
    Enum-like class representing the confidence level of whether a variable is tainted.

    - Tainted (1.0): The variable is known to be tainted.
    - MaybeTainted (0.5): The variable might be tainted.
    - NotTainted (0.0): The variable is known to be clean.
    """

    Tainted = 1.0
    MaybeTainted = 0.5
    NotTainted = 0.0


@dataclass
class TaintedGlobal:
    """
    Represents a tainted global variable within the analysis.

    This object tracks metadata related to global variables that are determined to be tainted
    based on static analysis of MLIL operations. It includes the symbolic reference, the
    confidence level of the taint, and contextual information like the location and pointer
    expression used to reference the variable.

    Attributes:
        variable (str): The name of the global variable as a string.
        confidence_level (TaintConfidence): How confidently this global is considered tainted.
        loc_address (int): The address where the taint was observed.
        const_ptr (MediumLevelILConstPtr): The IL constant pointer used to reference the global.
        symbol_object (CoreSymbol): The Binary Ninja symbol representing the global variable.
    """

    def __init__(
        self,
        variable: str,
        confidence_level: TaintConfidence,
        loc_address: int,
        const_ptr: MediumLevelILConstPtr,
        symbol_object: CoreSymbol,
    ):
        self.variable = variable
        self.confidence_level = confidence_level
        self.loc_address = loc_address
        self.const_ptr = const_ptr
        self.symbol_object = symbol_object

    def __eq__(self, other):
        if not isinstance(other, TaintedGlobal):
            return False

        return (
            self.variable == other.variable
            and self.confidence_level == other.confidence_level
            and self.loc_address == other.loc_address
            and self.const_ptr == other.const_ptr
            and self.symbol_object == other.symbol_object
        )

    def __hash__(self):
        return hash(
            (
                self.variable,
                self.confidence_level,
                self.loc_address,
                self.const_ptr.value,
                self.symbol_object,
            )
        )

    def __repr__(self):
        if self.confidence_level == TaintConfidence.Tainted:
            return f"{Fore.RESET}[{Fore.CYAN}{self.variable}{Fore.RESET}] -> [{Fore.LIGHTBLACK_EX}Tainted{Fore.RESET}]"
        elif self.confidence_level == TaintConfidence.MaybeTainted:
            return f"{Fore.RESET}[{Fore.CYAN}{self.variable}{Fore.RESET}] -> [{Fore.LIGHTMAGENTA_EX}Maybe Tainted{Fore.RESET}]"
        elif self.confidence_level == TaintConfidence.NotTainted:
            return f"{Fore.RESET}[{Fore.CYAN}{self.variable}{Fore.RESET}] -> [{Fore.LIGHTGREEN_EX}Not Tainted]{Fore.RESET}]"


@dataclass
class TaintedVar:
    """
    This class is used for representing each tainted variable we gather.
    """

    def __init__(
        self,
        variable: Variable | SSAVariable,
        confidence_level: TaintConfidence,
        loc_address: int,
    ):
        self.variable: Variable = variable  # Tainted Variable
        self.confidence_level: TaintConfidence = (
            confidence_level  # confidence level of being tainted
        )
        self.loc_address: int = (
            loc_address  # loc address of where the variable was found to be tainted
        )

    def __eq__(self, other):
        if not isinstance(other, TaintedVar):
            return False

        return (
            self.variable == other.variable
            and self.confidence_level == other.confidence_level
            and self.loc_address == other.loc_address
        )

    def __hash__(self):
        return hash(
            (
                self.variable,
                self.confidence_level,
                self.loc_address,
            )
        )

    def __repr__(self):
        if self.confidence_level == TaintConfidence.Tainted:
            return f"[{Fore.CYAN}{self.variable}{Fore.RESET}] -> [{Fore.LIGHTBLACK_EX}Tainted{Fore.RESET}]"
        elif self.confidence_level == TaintConfidence.MaybeTainted:
            return f"[{Fore.CYAN}{self.variable}{Fore.RESET}] -> [{Fore.LIGHTMAGENTA_EX}Maybe Tainted{Fore.RESET}]"
        elif self.confidence_level == TaintConfidence.NotTainted:
            return f"[{Fore.CYAN}{self.variable}{Fore.RESET}] -> [{Fore.LIGHTGREEN_EX}Not Tainted]{Fore.RESET}]"


class SliceType:
    """
    Enum for taint slicing direction.

    Attributes:
        Forward (int): Forward slicing (from source to sink).
        Backward (int): Backward slicing (from sink to source).
    """

    Forward = 0x0
    Backward = 0x1


class SlicingID:
    """
    Enum for the kind of variable being sliced.

    Attributes:
        FunctionVar (int): A standard function-local variable.
        FunctionParam (int): A formal function parameter.
        GlobalVar (int): A global variable symbol.
        StructMember (int): A member of a struct.
    """

    FunctionVar = 0x10
    FunctionParam = 0x20
    GlobalVar = 0x30
    StructMember = 0x40


class OutputMode:
    """
    Enum for how to return or display taint analysis output.

    Attributes:
        Returned (int): Return the data programmatically.
        Printed (int): Print the data to standard output.
    """

    Returned = 0x0
    Printed = 0x1


@dataclass
class TaintedVarOffset:
    """
    Used for tracking and holding data for variables from within MLIL_STORE/MLIL_LOAD operations
    """

    def __init__(
        self,
        variable: Variable,
        offset: int,
        offset_var: Union[
            TaintedVar, TaintedGlobal, "TaintedVarOffset", "TaintedStructMember"
        ],
        confidence_level: TaintConfidence,
        loc_address: int,
        targ_function: Function,
    ):
        self.variable = variable
        self.offset = offset
        self.confidence_level = confidence_level
        self.loc_address = loc_address
        self.offset_var = offset_var
        self.function = targ_function
        self.name = str(variable)

    def __eq__(self, other):
        if not isinstance(other, TaintedVarOffset):
            return False
        return (
            self.variable == other.variable
            and self.offset == other.offset
            and self.confidence_level == other.confidence_level
            and self.loc_address == other.loc_address
            and self.offset_var == other.offset_var
            and self.function == other.function
        )

    def __hash__(self):
        return hash(
            (
                self.variable,
                self.offset,
                self.confidence_level,
                self.loc_address,
                self.variable.function,
                self.function,
            )
        )

    def __repr__(self):
        var_taint = self.confidence_level
        offset_var_taint = self.offset_var.confidence_level if self.offset_var else None

        if (
            var_taint == TaintConfidence.Tainted
            and offset_var_taint == TaintConfidence.Tainted
        ):
            taint_status = (
                f"{Fore.LIGHTBLACK_EX}ReferenceVar + OffsetVar Tainted{Fore.RESET}"
            )
        elif var_taint == TaintConfidence.Tainted:
            taint_status = (
                f"{Fore.LIGHTBLACK_EX}Byte(s) at reference Tainted{Fore.RESET}"
            )
        elif offset_var_taint == TaintConfidence.Tainted:
            taint_status = f"{Fore.LIGHTBLACK_EX}OffsetVar Tainted{Fore.RESET}"
        elif (
            var_taint == TaintConfidence.MaybeTainted
            and offset_var_taint == TaintConfidence.MaybeTainted
        ):
            taint_status = f"{Fore.LIGHTMAGENTA_EX}ReferenceVar + OffsetVar Maybe Tainted{Fore.RESET}"
        elif var_taint == TaintConfidence.MaybeTainted:
            taint_status = (
                f"{Fore.LIGHTMAGENTA_EX}Byte(s) at reference Maybe Tainted{Fore.RESET}"
            )
        elif offset_var_taint == TaintConfidence.MaybeTainted:
            taint_status = f"{Fore.LIGHTMAGENTA_EX}OffsetVar Maybe Tainted{Fore.RESET}"
        else:
            taint_status = f"{Fore.LIGHTGREEN_EX}Not Tainted{Fore.RESET}"

        is_load = isinstance(
            self.function.get_llil_at(self.loc_address).mlil.src, MediumLevelILLoad
        )

        if self.offset_var is None:
            # Case: simple var + constant offset
            return (
                f"[&{Fore.CYAN}{self.variable}{Fore.RESET} + {Fore.CYAN}{self.offset:#0x}{Fore.RESET}] -> "
                f"[{taint_status}]"
            )

        if is_load:
            return (
                f"[&{Fore.CYAN}{self.variable}{Fore.RESET} + "
                f"{Fore.CYAN}{self.offset_var.variable}{Fore.RESET}] -> "
                f"[{taint_status}]"
            )
        else:
            return (
                f"[&{Fore.CYAN}{self.variable}{Fore.RESET}:{Fore.CYAN}{self.offset:#0x}{Fore.RESET} + "
                f"{Fore.CYAN}{self.offset_var.variable}{Fore.RESET}] -> "
                f"[{taint_status}]"
            )


class BGInit:
    def __init__(self, target_bin: str, libraries: list = None):
        if libraries is None:
            libraries = []
        self.target_bin = target_bin
        self.libraries = libraries
        self.cache_folder_name = "bg_cache"
        self.cache_folder_path: str = ""

    def _get_user_data_dir(self):
        """
        Returns a parent directory path where persistent application data can be stored.

        Linux: ~/.local/share
        macOS: ~/Library/Application Support
        Windows: C:/Users/<USER>/AppData/Roaming

        :return: User Data Path
        """
        home = pathlib.Path.home()

        system_paths = {
            "win32": home / "AppData/Roaming",
            "linux": home / ".local/share",
            "darwin": home / "Library/Application Support",
        }

        if sys.platform not in system_paths:
            raise SystemError(
                f'Unknown System Platform: {sys.platform}. Only supports {", ".join(list(system_paths.keys()))}'
            )
        data_path = system_paths[sys.platform]

        return data_path

    def _get_file_hash(self, file_path):
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

    def _get_cache_filename(self, lib_fp):
        lib_hash = self._get_file_hash(lib_fp)
        lib_name = os.path.basename(lib_fp)
        return f"{self.cache_folder_path}/{lib_name}_{lib_hash}.bndb"

    def _match_imported_functions_to_libraries(self, bv):
        self.cache_folder_path = (
            f"{self._get_user_data_dir()}/bingoggles/{self.cache_folder_name}"
        )
        if not os.path.exists(self.cache_folder_path):
            os.makedirs(self.cache_folder_path, exist_ok=True)

        mapped = {}
        for lib in self.libraries:
            cache_file = self._get_cache_filename(lib)
            if os.path.exists(cache_file):
                print(
                    f"[{Fore.CYAN}INFO{Fore.RESET}] Loading analysis from cache for {lib}"
                )
                lib_bv = bv.load(os.path.abspath(cache_file))
                mapped[lib] = lib_bv

            else:
                print(f"[{Fore.CYAN}INFO{Fore.RESET}] Analyzing and caching {lib}")
                lib_bv = bv.load(lib)
                if lib_bv:
                    lib_bv.create_database(os.path.abspath(cache_file))
                    mapped[lib] = lib_bv

        return mapped

    def init(self):
        with Progress() as progress:
            task_connect = progress.add_task("[cyan]Connecting to API...", total=1)
            progress.update(task_connect, advance=1)

            task_load_bin = progress.add_task("[green]Loading binary...", total=1)
            bv = bn.load(self.target_bin)
            progress.update(task_load_bin, advance=1)

        imported_functions_mapped = None

        if len(self.libraries) > 0:
            with Status("[magenta]Matching imports to libraries...", spinner="dots"):
                imported_functions_mapped = self._match_imported_functions_to_libraries(
                    bv
                )

            return bv, imported_functions_mapped

        else:
            return bv, None


class BGInitRpyc(BGInit):
    """
    Initializes an RPyC connection to interact with a target binary and its associated libraries,
    and sets up the BinGoggles state for analysis, caching, and loading the libraries.

    This class sets up a remote procedure call (RPyC) connection to a specified host and port,
    targeting a particular binary and its dependent libraries. The timeout for the connection
    is adjusted based on the number of libraries provided. Additionally, it handles the setup
    of the BinGoggles state for performing binary analysis, caching results, and loading the
    necessary libraries.
    """

    def __init__(
        self,
        target_bin: str,
        libraries: list = None,
        host: str = "127.0.0.1",
        port: int = 18812,
        timeout: int = 520,
    ):
        if libraries is None:
            libraries = []
        super().__init__(target_bin=target_bin, libraries=libraries)
        self.host = host
        self.port = port
        self.timeout = timeout * len(libraries) if libraries else 1

    def _api_connect(self):
        try:
            rpyc.core.protocol.DEFAULT_CONFIG["sync_request_timeout"] = self.timeout
            return rpyc.connect(
                self.host,
                self.port,
                config=rpyc.core.protocol.DEFAULT_CONFIG,
            )
        except (socket.error, EOFError, socket.timeout) as e:
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port} - {e}")

    def init(self):
        with Progress() as progress:
            task_connect = progress.add_task("[cyan]Connecting to API...", total=1)
            c = self._api_connect()
            progress.update(task_connect, advance=1)

            task_load_bin = progress.add_task("[green]Loading binary...", total=1)
            bn = c.root.binaryninja
            bv = bn.load(self.target_bin)
            progress.update(task_load_bin, advance=1)

        imported_functions_mapped = None

        if len(self.libraries) > 0:
            # This is temporary while bingoggles is still in development, long term vision hopefully some of this can be automated
            answer = input("Load libraries? [y/n]: ")
            if answer == "" or answer == "n":
                return bv, None
            else:
                imported_functions_mapped = self._match_imported_functions_to_libraries(
                    bv
                )
                return bv, imported_functions_mapped

        else:
            return bv, None


@dataclass
class TaintedStructMember:
    def __init__(
        self,
        loc_address: int,
        member: str,
        offset: int,
        hlil_var: Variable,
        variable: Variable,
        confidence_level: TaintConfidence,
    ):
        self.loc_address = loc_address
        self.member = member
        self.offset = offset
        self.hlil_var = hlil_var
        self.variable = variable  # this is the MLIL variable, naming it variable to keep things consisitent in the bingoggles structure
        self.confidence_level = confidence_level

    def __hash__(self):
        return hash(
            (
                self.loc_address,
                self.member,
                self.offset,
                self.hlil_var,
                self.variable,
                self.confidence_level,
            )
        )

    def __repr__(self):
        if self.confidence_level == TaintConfidence.Tainted:
            return (
                f"[{Fore.CYAN}{self.hlil_var}{Fore.RESET}]"
                f"->{self.member} @ {self.loc_address:#0x} "
                f"[{Fore.LIGHTBLACK_EX}Tainted{Fore.RESET}]"
            )
        elif self.confidence_level == TaintConfidence.MaybeTainted:
            return (
                f"[{Fore.CYAN}{self.hlil_var}{Fore.RESET}]"
                f" -> {self.member} @ {self.loc_address:#0x} "
                f"[{Fore.LIGHTMAGENTA_EX}Maybe Tainted{Fore.RESET}]"
            )
        elif self.confidence_level == TaintConfidence.NotTainted:
            return (
                f"[{Fore.CYAN}{self.hlil_var}{Fore.RESET}]"
                f" -> {self.member} @ {self.loc_address:#0x} "
                f"[{Fore.LIGHTGREEN_EX}Not Tainted{Fore.RESET}]"
            )


@dataclass
class TaintTarget:
    """
    Represents the initial location and variable to start taint analysis from.

    Attributes:
        loc_address (int): Address of the instruction referencing the variable.
        variable (Variable | str): The variable to trace (either a Binja object or its name).
    """

    def __init__(self, loc_address: int, variable: Variable | str):
        self.loc_address = loc_address
        self.variable = variable

    def __hash__(self):
        return hash(
            (
                self.loc_address,
                self.variable,
            )
        )

    def __repr__(self):
        return f"[{Fore.LIGHTBLUE_EX}TaintTarget{Fore.RESET}] -> {self.variable} @ {self.loc_address}"


@dataclass
class InterprocTaintResult:
    def __init__(
        self,
        tainted_param_names: set,
        tainted_param_map: dict,
        original_tainted_variables: Union[list[TaintedVar], TaintedVar],
        is_return_tainted: bool,
        target_function_params: List[Variable],
    ):
        self.tainted_param_names = tainted_param_names
        self.tainted_param_map = tainted_param_map
        self.original_tainted_variables = original_tainted_variables
        self.is_return_tainted = is_return_tainted
        self.target_function_params = target_function_params

    def __hash__(self):
        return hash(
            (
                tuple(self.tainted_param_names),
                frozenset(self.tainted_param_map.items()),
                tuple(self.original_tainted_variables),
                self.is_return_tainted,
                tuple(self.target_function_params),
            )
        )

    def __repr__(self):
        return (
            f"{Fore.MAGENTA}Tainted Parameter Names:{Fore.RESET} {self.tainted_param_names}\n"
            f"{Fore.CYAN}Original Tainted Variables:{Fore.RESET} {self.original_tainted_variables}\n"
            f"{Fore.YELLOW}Is Return Tainted:{Fore.RESET} {self.is_return_tainted}\n"
            f"{Fore.GREEN}Tainted Parameter Map:{Fore.RESET} {self.tainted_param_map}\n"
            f"{Fore.BLUE}Target Function Parameters:{Fore.RESET} {self.target_function_params}"
        )


class TaintedLOC:
    """
    Represents a single tainted instruction in the variable flow analysis.

    This class holds the metadata for a specific line of code (MediumLevelILInstruction)
    that has been identified as part of a tainted data flow path. It links the instruction
    to the variable being tracked, the variable it may have propagated from, and the
    confidence level assigned to the taint at that point.

    Attributes:
        loc (MediumLevelILInstruction): The MLIL instruction involved in the tainted operation.
        addr (int): The address of the instruction in the binary.
        target_var (Union[TaintedVar, TaintedVarOffset, TaintedGlobal, TaintedStructMember]):
            The variable being tracked as tainted at this instruction.
        propagated_var (Variable | None): The variable from which the taint originated, if applicable.
        taint_confidence (TaintConfidence): The confidence level (Tainted, MaybeTainted, NotTainted).
        function_object (Function): The Binary Ninja function object this instruction belongs to.
    """

    def __init__(
        self,
        loc: MediumLevelILInstruction,  # Line of code
        addr: int,  # Address of the LOC
        target_var: Union[
            TaintedVar, TaintedVarOffset, TaintedGlobal, TaintedStructMember
        ],  # Target variable that we found this LOC with, (the variable we're tracking)
        propagated_var: Union[
            Variable | None
        ],  # Variable where target_var gets its data from (connected variable)
        taint_confidence: TaintConfidence,  # Confidence level of the LOC being tainted
        function_object: Function,  # Binary ninja function object
    ):
        self.loc = loc
        self.target_var = target_var
        self.propagated_var = propagated_var
        self.taint_confidence = taint_confidence
        self.addr = addr
        self.function_object = function_object

    def __repr__(self):
        if int(self.loc.operation) == int(MediumLevelILOperation.MLIL_CALL):
            function = self.function_object.view.get_function_at(
                self.loc.dest.value.value
            )
            function_name = (
                function.name if function else f"{self.loc.dest.value.value:#0x}"
            )

            loc_str = str(self.loc)
            loc_str = loc_str.replace(f"{self.loc.dest.value.value:#0x}", function_name)

            if self.taint_confidence == TaintConfidence.Tainted:
                return f"[{self.addr:#0x}] {Fore.CYAN}{loc_str}{Fore.RESET} -> {Fore.MAGENTA}{self.target_var.variable}{Fore.RESET} -> {Fore.RED}{self.propagated_var}{Fore.RESET} [{Fore.LIGHTBLACK_EX}Tainted{Fore.RESET}]"

            elif self.taint_confidence == TaintConfidence.MaybeTainted:
                return f"[{self.addr:#0x}] {Fore.CYAN}{loc_str}{Fore.RESET} -> {Fore.MAGENTA}{self.target_var.variable}{Fore.RESET} -> {Fore.RED}{self.propagated_var}{Fore.RESET} [{Fore.YELLOW}MaybeTainted{Fore.RESET}]"

        else:
            if self.taint_confidence == TaintConfidence.Tainted:
                return f"[{self.addr:#0x}] {Fore.CYAN}{self.loc}{Fore.RESET} -> {Fore.MAGENTA}{self.target_var.variable}{Fore.RESET} -> {Fore.RED}{self.propagated_var}{Fore.RESET} [{Fore.LIGHTBLACK_EX}Tainted{Fore.RESET}]"

            elif self.taint_confidence == TaintConfidence.MaybeTainted:
                return f"[{self.addr:#0x}] {Fore.CYAN}{self.loc}{Fore.RESET} -> {Fore.MAGENTA}{self.target_var.variable}{Fore.RESET} -> {Fore.RED}{self.propagated_var}{Fore.RESET} [{Fore.YELLOW}MaybeTainted{Fore.RESET}]"


@dataclass
class VulnReport:
    """
    Encapsulates data about a detected vulnerability, specifically
    the tainted execution path that leads to it.

    Attributes:
        vulnerable_path_data (List[TaintedLOC]): List of tainted code locations forming a vulnerable execution path.
    """

    def __init__(self, vulnerable_path_data: List[TaintedLOC]):
        self.vulnerable_path_data = vulnerable_path_data

    def __hash__(self):
        return hash(tuple(self.vulnerable_path_data))

    def __repr__(self):
        return f"VulnReport(vulnerable_path_data={self.vulnerable_path_data})"


class FunctionModel:
    def __init__(
        self,
        name: str,
        taint_sources: list[int],
        taint_destinations: list[int],
        taints_return: bool,
        taints_varargs: bool = False,
        vararg_start_index: Union[int, None] = None,
    ):
        self.name = name
        self.taint_sources = taint_sources
        self.taint_destinations = taint_destinations
        self.taints_return = taints_return
        self.taints_varargs = taints_varargs
        self.vararg_start_index = vararg_start_index

    def __repr__(self):
        return (
            f"FunctionModel(name='{self.name}', "
            f"taint_sources={self.taint_sources}, "
            f"taint_destinations={self.taint_destinations}, "
            f"taints_return={self.taints_return}, "
            f"taints_varargs={self.taints_varargs}, "
            f"vararg_start_index={self.vararg_start_index})"
        )


class TraceDecision(Enum):
    SKIP_AND_DISCARD = auto()  # Skip instruction, don't trace variable
    SKIP_AND_PROCESS = auto()  # Skip instruction, still trace variable
    PROCESS_AND_DISCARD = auto()  # Don't skip instruction, but discard variable (rare)
    PROCESS_AND_TRACE = auto()  # Normal tracing
