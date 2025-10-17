from dataclasses import dataclass
from binaryninja.variable import Variable
from binaryninja.function import Function
from binaryninja.mediumlevelil import (
    SSAVariable,
    MediumLevelILInstruction,
    MediumLevelILConstPtr,
    MediumLevelILOperation,
)
from binaryninja.types import CoreSymbol
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
class CallData:
    """
    Represents data associated with a function call during taint analysis.

    Attributes:
        call_params (list): The raw parameters of the function call as seen in the MLIL.
        call_object (Function): The Binary Ninja Function object representing the called function.
        function_call_params (List[SSAVariable]): The SSA variables representing the parameters
                                                  of the *called function* (callee's perspective).
        zipped_params (List[SSAVariable]): A list of SSA variables representing the parameters
                                           of the call, often zipped with the function's expected parameters.
        tainted_sub_params (List[SSAVariable]): A list of SSA variables within the called function
                                                that are identified as tainted due to the call.
    """

    def __init__(
        self,
        call_params: list,
        call_object: Function,
        function_call_params: List[SSAVariable],
        zipped_params: List[SSAVariable],
        tainted_sub_params: List[SSAVariable],
    ):
        self.call_params = call_params
        self.call_object = call_object
        self.function_call_params = function_call_params
        self.zipped_params = zipped_params
        self.tainted_sub_params = tainted_sub_params

    def __repr__(self) -> str:
        return (
            f"CallData(call_params={self.call_params!r}, call_object={self.call_object!r}, "
            f"function_call_params={self.function_call_params!r}, "
            f"zipped_params={self.zipped_params!r}, "
            f"tainted_sub_params={self.tainted_sub_params!r})"
        )


@dataclass
class LoadStoreData:
    """
    Represents data extracted from a load or store operation.

    This class encapsulates information about memory access, including the base address
    variable, the offset, and details about any tainted offset variables,
    along with confidence and location.

    Attributes:
        offset: The offset applied to the base address variable. Can be an integer or other type.
        addr_var (Union[Variable, SSAVariable]): The base address variable involved in the load/store.
        tainted_offset_var (Union["TaintedVar", "TaintedGlobal", "TaintedStructMember", "TaintedVarOffset"]):
            Information about a tainted variable contributing to the offset, if applicable.
        confidence_level (TaintConfidence): The confidence level of the taint.
        loc_address (int): The address of the MLIL instruction.
    """

    def __init__(
        self,
        offset,
        addr_var: Union[Variable, SSAVariable],
        tainted_offset_var: Union[
            "TaintedGlobal", "TaintedStructMember", "TaintedVarOffset", "TaintedVar"
        ],
        confidence_level: TaintConfidence,
        loc_address: int,
    ):
        self.offset = offset
        self.addr_var = addr_var
        self.tainted_offset_var = tainted_offset_var
        self.confidence_level = confidence_level
        self.loc_address = loc_address

    def __repr__(self):
        display_offset = (
            hex(self.offset) if isinstance(self.offset, int) else self.offset
        )
        confidence_str = {
            TaintConfidence.Tainted: "Tainted",
            TaintConfidence.MaybeTainted: "MaybeTainted",
            TaintConfidence.NotTainted: "NotTainted",
        }.get(self.confidence_level, str(self.confidence_level))

        tainted_var_info = ""
        if self.tainted_offset_var:
            tainted_var_info = f", offset_var={getattr(self.tainted_offset_var, 'variable', self.tainted_offset_var)}"

        return f"[LoadStoreData @ {self.loc_address:#x}]: {self.addr_var}:{display_offset}{tainted_var_info} [{confidence_str}]"

    def __eq__(self, other):
        if not isinstance(other, LoadStoreData):
            return NotImplemented

        return (
            self.offset == other.offset
            and self.addr_var == other.addr_var
            and self.offset_var_taintedvar == other.offset_var_taintedvar
            and self.confidence_level == other.confidence_level
            and self.loc_address == other.loc_address
        )

    def __hash__(self):
        return hash(
            (
                self.offset,
                self.addr_var,
                self.offset_var_taintedvar,
                self.confidence_level,
                self.loc_address,
            )
        )


@dataclass
class PseudoGlobalVariable:
    """
    Represents a lightweight global variable reference without requiring a complete Binary Ninja symbol object.

    This class provides a simplified way to track and reference global variables by name and address
    when a full CoreSymbol object might not be available or necessary.

    Attributes:
        name (str): The name of the global variable.
        address (int): The memory address where the global variable is located.
    """

    def __init__(
        self,
        name: str,
        address: int,
    ):
        self.name = name
        self.address = address

    def __eq__(self, other):
        if not isinstance(other, PseudoGlobalVariable):
            return False

        return self.name == other.name and self.address == other.address

    def __hash__(self):
        return hash(
            (
                self.name,
                self.address,
            )
        )

    def __repr__(self):
        return f"[{self.name} @ {self.address:#0x}]"


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
        symbol_object: Union[CoreSymbol, PseudoGlobalVariable],
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
            return f"[{self.variable}] -> [Tainted]"
        elif self.confidence_level == TaintConfidence.MaybeTainted:
            return f"[{self.variable}] -> [Maybe Tainted]"
        elif self.confidence_level == TaintConfidence.NotTainted:
            return f"[{self.variable}] -> [Not Tainted]"


@dataclass
class TaintedVar:
    """
    Represents a single tainted local/SSA variable observed during analysis.

    Purpose:
        Records that a specific MLIL variable (or its SSA form) is tainted at a particular
        program location, along with the confidence assigned to that taint.

    Attributes:
        variable (Variable | SSAVariable): The Binary Ninja variable (or SSA variable) that is tainted.
        confidence_level (TaintConfidence): Confidence that the variable is tainted
            (Tainted, MaybeTainted, or NotTainted).
        loc_address (int): Address of the MLIL instruction where this taint was recorded.
    """

    def __init__(
        self,
        variable: Variable | SSAVariable,
        confidence_level: TaintConfidence,
        loc_address: int,
    ):
        self.variable: Variable = variable
        self.confidence_level: TaintConfidence = (
            confidence_level
        )
        self.loc_address: int = (
            loc_address
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
            return f"[{self.variable}] -> [Tainted]"
        elif self.confidence_level == TaintConfidence.MaybeTainted:
            return f"[{self.variable}] -> [Maybe Tainted]"
        elif self.confidence_level == TaintConfidence.NotTainted:
            return f"[{self.variable}] -> [Not Tainted]"


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
    Represents a tainted memory reference composed of a base variable and an optional offset.

    This type models address expressions seen in MLIL load/store operations (e.g., [&base + off]),
    tracking both the taint on the referenced memory (base) and the taint coming from a symbolic
    offset variable (if any). It is used to propagate taint when memory is accessed via an address
    computed from a stack/local variable plus a constant or another variable.

    Attributes:
        variable (Variable):
            The base address variable (e.g., var_35 in [&var_35 + rax_7]).
        offset (int | MediumLevelILConst | MediumLevelILConstPtr | None):
            The constant offset applied to the base, if present. May be None when the offset
            is symbolic (i.e., provided via offset_var).
        offset_var (TaintedVar | TaintedGlobal | TaintedVarOffset | TaintedStructMember | None):
            The tainted entity contributing to a symbolic/dynamic offset (e.g., rax_7). None if
            the offset is constant or absent.
        confidence_level (TaintConfidence):
            Taint confidence for the referenced memory at [variable + offset/offset_var].
            This describes the taint of the memory access, not necessarily the offset_var itself.
        loc_address (int):
            Address of the MLIL instruction that produced this reference.
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
    ):
        self.variable = variable
        self.offset = offset
        self.confidence_level = confidence_level
        self.loc_address = loc_address
        self.offset_var = offset_var
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
        )

    def __hash__(self):
        return hash(
            (
                self.variable,
                self.offset,
                self.confidence_level,
                self.loc_address,
            )
        )

    def __repr__(self):
        var_taint = self.confidence_level
        offset_var_taint = self.offset_var.confidence_level if self.offset_var else None

        if (
            var_taint == TaintConfidence.Tainted
            and offset_var_taint == TaintConfidence.Tainted
        ):
            taint_status = "ReferenceVar + OffsetVar Tainted"
        elif var_taint == TaintConfidence.Tainted:
            taint_status = "Byte(s) at reference Tainted"
        elif offset_var_taint == TaintConfidence.Tainted:
            taint_status = "OffsetVar Tainted"
        elif (
            var_taint == TaintConfidence.MaybeTainted
            and offset_var_taint == TaintConfidence.MaybeTainted
        ):
            taint_status = "ReferenceVar + OffsetVar Maybe Tainted"
        elif var_taint == TaintConfidence.MaybeTainted:
            taint_status = "Byte(s) at reference Maybe Tainted"
        elif offset_var_taint == TaintConfidence.MaybeTainted:
            taint_status = "OffsetVar Maybe Tainted"
        else:
            taint_status = "Not Tainted"

        parts = [f"&{self.variable}"]

        if self.offset is not None:
            if hasattr(self.offset, "value"):
                parts.append(f"+ {self.offset.value.value:#0x}")
            else:
                parts.append(f"+ {self.offset}")
        elif self.offset_var is not None:
            parts.append(f"+ {getattr(self.offset_var, 'variable', self.offset_var)}")

        addr_str = " ".join(parts)

        return f"[{addr_str}] -> [{taint_status}]"


class BGInit:
    """
    Initializes BinGoggles analysis state for a local binary and optional libraries.

    Parameters:
        target_bin (str): Absolute or relative path to the target binary to analyze.
        libraries (list[str] | None): Optional list of library paths to preload and cache
            for import matching.

    Attributes:
        target_bin (str): Path to the target binary.
        libraries (list[str]): List of library paths to consider for matching imported functions.
        cache_folder_name (str): Directory name used to store cached .bndb files.
        cache_folder_path (str): Resolved path to the cache directory (set at runtime).

    Notes:
        - init() loads the Binary Ninja BinaryView for target_bin and returns (bv, libraries_mapped).
        - When libraries are provided, matching/caching occurs.
    """
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
                print(f"[INFO] Loading analysis from cache for {lib}")
                lib_bv = bv.load(os.path.abspath(cache_file))
                mapped[lib] = lib_bv

            else:
                print(f"[INFO] Analyzing and caching {lib}")
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
    """
    Represents a tainted access to a structure/aggregate member.
    Records that a specific field within a struct-like object is tainted at a given
    program location. Keeps both the HLIL variable that expresses the field access
    and the underlying MLIL base variable that stores the data.

    Attributes:
        loc_address (int): Address of the MLIL instruction where the field access occurs.
        member (str): Field name or textual representation of the accessed member.
        offset (int): Byte offset of the member within the base object.
        hlil_var (Variable): HLIL variable in the field reference (field-aware, higher-level).
        variable (Variable): MLIL base variable backing the struct storage.
        confidence_level (TaintConfidence): Confidence assigned to this tainted field access.
    """
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
                f"[{self.hlil_var}]"
                f"->{self.member} @ {self.loc_address:#0x} "
                f"[Tainted]"
            )
        elif self.confidence_level == TaintConfidence.MaybeTainted:
            return (
                f"[{self.hlil_var}]"
                f" -> {self.member} @ {self.loc_address:#0x} "
                f"[Maybe Tainted]"
            )
        elif self.confidence_level == TaintConfidence.NotTainted:
            return (
                f"[{self.hlil_var}]"
                f" -> {self.member} @ {self.loc_address:#0x} "
                f"[Not Tainted]"
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
        return f"[TaintTarget] -> {self.variable} @ {self.loc_address}"


@dataclass
class InterprocTaintResult:
    def __init__(
        self,
        tainted_param_names: set,
        tainted_param_map: dict,
        original_tainted_variables: Union[List[TaintedVar], TaintedVar],
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
            f"Tainted Parameter Names: {self.tainted_param_names}\n"
            f"Original Tainted Variables: {self.original_tainted_variables}\n"
            f"Is Return Tainted: {self.is_return_tainted}\n"
            f"Tainted Parameter Map: {self.tainted_param_map}\n"
            f"Target Function Parameters: {self.target_function_params}"
        )


@dataclass
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
        target_var (Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ]):
            The variable being tracked as tainted at this instruction.
        propagated_var (Variable | None): The variable from which the taint originated, if applicable.
        taint_confidence (TaintConfidence): The confidence level (Tainted, MaybeTainted, NotTainted).
        function_node (Function): The Binary Ninja function object this instruction belongs to.
    """

    def __init__(
        self,
        loc: MediumLevelILInstruction,  # Line of code
        addr: int,  # Address of the LOC
        target_var: Union[
            TaintedGlobal, TaintedStructMember, TaintedVarOffset, TaintedVar
        ],  # Target variable that we found this LOC with, (the variable we're tracking)
        propagated_var: Union[
            Variable | None
        ],  # Variable where target_var gets its data from (connected variable)
        taint_confidence: TaintConfidence,  # Confidence level of the LOC being tainted
        function_node: Function,  # Binary ninja function object
    ):
        self.loc = loc
        self.target_var = target_var
        self.propagated_var = propagated_var
        self.taint_confidence = taint_confidence
        self.addr = addr
        self.function_node = function_node

    def __hash__(self):
        return hash(
            (
                self.addr,
                self.target_var,
                self.propagated_var,
                self.taint_confidence,
                self.function_node,
            )
        )

    def __repr__(self):
        if self.loc.operation.value == MediumLevelILOperation.MLIL_CALL.value:
            function = self.function_node.view.get_function_at(
                self.loc.dest.value.value
            )
            function_name = (
                function.name if function else f"{self.loc.dest.value.value:#0x}"
            )

            loc_str = str(self.loc)
            loc_str = loc_str.replace(f"{self.loc.dest.value.value:#0x}", function_name)

            if self.taint_confidence == TaintConfidence.Tainted:
                return f"[{self.addr:#0x}] {loc_str} -> {self.target_var.variable} -> {self.propagated_var} [Tainted]"

            elif self.taint_confidence == TaintConfidence.MaybeTainted:
                return f"[{self.addr:#0x}] {loc_str} -> {self.target_var.variable} -> {self.propagated_var} [MaybeTainted]"
        else:
            if self.taint_confidence == TaintConfidence.Tainted:
                return f"[{self.addr:#0x}] {self.loc} -> {self.target_var.variable} -> {self.propagated_var} [Tainted]"

            elif self.taint_confidence == TaintConfidence.MaybeTainted:
                return f"[{self.addr:#0x}] {self.loc} -> {self.target_var.variable} -> {self.propagated_var} [MaybeTainted]"


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


@dataclass
class FunctionModel:
    """
    Represents a model of a function for taint analysis.

    Attributes:
        name (str): The function's name.
        taint_sources (List[int]): Indices of parameters that are taint sources.
        taint_destinations (List[int]): Indices of parameters that are taint sinks/destinations.
        taints_return (bool): Whether the function's return value is tainted by any input.
        taints_varargs (bool): Whether the function taints variable arguments.
        vararg_start_index (int|None): Index where varargs start, if applicable.
    """

    def __init__(
        self,
        name: str,
        taint_sources: List[int],
        taint_destinations: List[int],
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
    """
    Enum for decisions made during taint tracing.

    Values:
        SKIP_AND_DISCARD: Skip instruction, don't trace variable.
        SKIP_AND_PROCESS: Skip instruction, still trace variable.
        PROCESS_AND_DISCARD: Don't skip instruction, but discard variable (rare).
        PROCESS_AND_TRACE: Normal tracing.
    """

    SKIP_AND_DISCARD = auto()  # Skip instruction, don't trace variable
    SKIP_AND_PROCESS = auto()  # Skip instruction, still trace variable
    PROCESS_AND_DISCARD = auto()  # Don't skip instruction, but discard variable (rare)
    PROCESS_AND_TRACE = auto()  # Normal tracing
