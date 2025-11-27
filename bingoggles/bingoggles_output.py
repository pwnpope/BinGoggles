import re
from itertools import takewhile
import textwrap
import os
from .bingoggles_types import *
from typing import *
from colorama import Fore

# Add global options with defaults
USE_COLOR = True
LOG_FILE = None


# ANSI handling helpers to keep colored output aligned
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _visible_len(s: str) -> int:
    return len(_strip_ansi(s))


def _truncate_visible(s: str, width: int) -> str:
    """Truncate a possibly ANSI-colored string to a visible width, preserving ANSI codes."""
    if width <= 0:
        return ""
    if _visible_len(s) <= width:
        return s
    # Reserve one char for ellipsis if possible
    target = max(0, width - 1)
    out: List[str] = []
    vis = 0
    i = 0
    while i < len(s) and vis < target:
        m = _ANSI_RE.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
        else:
            out.append(s[i])
            i += 1
            vis += 1
    if width > 0:
        out.append("…")
    return "".join(out)


def _pad_right_visible(s: str, width: int) -> str:
    pad = max(0, width - _visible_len(s))
    return s + (" " * pad)


def set_output_options(use_color: bool = True, log_file: Optional[str] = None):
    """
    Configure output options for pretty printing.

    Args:
        use_color (bool): Whether to use colored output. Default is True.
        log_file (str, optional): Path to log file for saving output. Default is None (no logging).
    """
    global USE_COLOR, LOG_FILE
    USE_COLOR = use_color
    LOG_FILE = log_file

    # Create log directory if it doesn't exist
    if LOG_FILE and not os.path.exists(os.path.dirname(LOG_FILE)):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def colorize(text: str, color: str) -> str:
    """Apply color to text if coloring is enabled"""
    if USE_COLOR:
        return f"{color}{text}{Fore.RESET}"
    return text


def log_output(text: str):
    """Write output to log file if logging is enabled"""
    if LOG_FILE:
        # Strip ANSI color codes for log file
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", text)
        with open(LOG_FILE, "a") as f:
            f.write(clean_text + "\n")


def create_ascii_table(headers, rows, min_widths=None, max_widths=None):
    """
    Creates a well-formatted ASCII table with proper alignment.

    - Single line per row (no wrapping). Long cells are truncated with an ellipsis.
    - Width calculations ignore ANSI sequences so colors don't break alignment.

    Args:
        headers (list): List of column headers
        rows (list): List of rows, where each row is a list of cell values
        min_widths (list, optional): Minimum width for each column
        max_widths (list, optional): Maximum width for each column

    Returns:
        list: List of strings representing the formatted table
    """
    col_count = len(headers)
    # Defaults and normalization
    min_widths = (min_widths or [3] * col_count)[:col_count]
    max_widths = (max_widths or [30] * col_count)[:col_count]

    # Normalize rows: strings, single-line, compact spaces
    norm_rows: List[List[str]] = []
    for r in rows:
        r = list(r) + [""] * (col_count - len(r))
        cells: List[str] = []
        for c in r[:col_count]:
            s = "" if c is None else str(c)
            s = s.replace("\n", " ").replace("\r", " ")
            s = re.sub(r"\s+", " ", s).strip()
            cells.append(s)
        norm_rows.append(cells)

    # Compute column widths based on visible length
    col_widths: List[int] = []
    for i in range(col_count):
        header_len = _visible_len(str(headers[i]))
        max_cell_len = max([_visible_len(row[i]) for row in norm_rows], default=0)
        width = max(header_len, min_widths[i], min(max_widths[i], max_cell_len))
        col_widths.append(width)

    # Build table
    lines: List[str] = []

    # Borders include 2 spaces of padding per column
    def border(left: str, mid: str, right: str, fill: str) -> str:
        segs = [fill * (w + 2) for w in col_widths]
        return left + mid.join(segs) + right

    lines.append(border("┌", "┬", "┐", "─"))

    # Header line
    header_parts: List[str] = ["│"]
    for i, h in enumerate(headers):
        text = str(h)
        text = _truncate_visible(text, col_widths[i])
        text = _pad_right_visible(text, col_widths[i])
        header_parts.append(" " + text + " ")
        header_parts.append("│")
    lines.append("".join(header_parts))

    lines.append(border("├", "┼", "┤", "─"))

    # Data rows (single line per row)
    for row in norm_rows:
        parts: List[str] = ["│"]
        for i, cell in enumerate(row):
            cell = _truncate_visible(cell, col_widths[i])
            cell = _pad_right_visible(cell, col_widths[i])
            parts.append(" " + cell + " ")
            parts.append("│")
        lines.append("".join(parts))

    lines.append(border("└", "┴", "┘", "─"))
    return lines


def format_instruction(instruction: str) -> str:
    """
    Formats a disassembled instruction string for improved readability.

    Args:
        instruction (str): The instruction string to format.

    Returns:
        str: The formatted instruction string.
    """
    instruction = instruction.replace("=", " = ")
    instruction = re.sub(r",\s*", ", ", instruction)
    instruction = re.sub(r"\s{2,}", " ", instruction)
    return instruction.strip()


def pretty_print_path_data(path_data: List):
    """
    Prints a formatted summary of taint analysis path data, with color and boxed output.
    Uses create_ascii_table for consistent formatting.
    """
    if not path_data:
        # :TODO implement some logging here to display why there may be no taint data to display
        print("No taint data to display")
        return

    raw_rows = []
    color_rows = []

    for bingoggles_data in path_data:
        instr_index = str(bingoggles_data.loc.instr_index)
        split_loc = str(bingoggles_data).split(" ")
        loc_data = list(takewhile(lambda x: x != "->", split_loc))
        loc_address = loc_data.pop(0)
        loc = " ".join(loc_data)
        arrow_index = split_loc.index("->")
        right = split_loc[arrow_index + 1 :]

        if len(right) == 4:
            tainted_var, _, propagated_var, confidence = right
        elif len(right) == 3:
            tainted_var, propagated_var, confidence = right
        elif len(right) == 2:
            tainted_var, confidence = right
            propagated_var = "None"
        else:
            tainted_var = propagated_var = confidence = "?"

        formatted_loc = format_instruction(loc)
        formatted_loc = formatted_loc.replace("\n", " ").replace("\r", " ")
        formatted_loc = re.sub(r"\s+", " ", formatted_loc).strip()

        # Do not rely on textwrap; we keep single-line and truncate in the table function
        raw_row = [
            instr_index,
            loc_address,
            formatted_loc,
            tainted_var,
            propagated_var,
            confidence,
        ]
        raw_rows.append(raw_row)

        conf_col = confidence
        if "[Tainted]" in confidence:
            conf_col = colorize(confidence, Fore.RED)
        elif "[Maybe" in confidence:
            conf_col = colorize(confidence, Fore.YELLOW)
        elif "[Not" in confidence:
            conf_col = colorize(confidence, Fore.GREEN)

        color_row = [
            instr_index,
            colorize(loc_address, Fore.CYAN),
            colorize(formatted_loc, Fore.WHITE),
            colorize(tainted_var, Fore.MAGENTA),
            colorize(propagated_var, Fore.BLUE),
            conf_col,
        ]
        color_rows.append(color_row)

    headers = [
        "Idx",
        "Address",
        "LOC",
        "Target Var",
        "Propagated Var",
        "Taint Confidence",
    ]

    # Fixed column widths to prevent warping; table handles truncation without wrapping
    min_widths = [3, 12, 45, 12, 16, 17]
    max_widths = [6, 14, 60, 16, 20, 20]

    table_lines = create_ascii_table(
        headers,
        color_rows if USE_COLOR else raw_rows,
        min_widths,
        max_widths,
    )

    for line in table_lines:
        print(line)
        log_output(line)


def render_sliced_output(
    sliced_func: Union[Dict, List],
    output_mode: OutputMode,
    func_obj: Function,
    propagated_vars: List,
    verbose: bool,
    use_color: bool = True,
    log_file: Optional[str] = None,
) -> Union[None, Tuple[List, str, List]]:
    """
    Renders or returns the output of a sliced function based on the specified output mode.

    Args:
        sliced_func (dict): A mapping from keys (usually address/function) to lists of TaintedLOC or TaintedVar.
        output_mode (OutputMode): Specifies how to present the output.
        func_obj (Function): The function object being analyzed.
        propagated_vars (list): List of propagated variables (TaintedVar objects).
        verbose (bool): Whether to print output when returning results.
        use_color (bool): Whether to use colored output. Default is True.
        log_file (str, optional): Path to save output to a log file. Default is None (no logging).

    Returns:
        tuple | None: Returns a tuple of (tainted_locs, func_name, propagated_vars) when `Returned`, otherwise None.
    """
    # Set output options
    set_output_options(use_color=use_color, log_file=log_file)

    if output_mode == OutputMode.Printed:
        pretty_print_path_data(sliced_func)

    elif output_mode == OutputMode.Returned:
        if verbose:
            pretty_print_path_data(sliced_func)
        return [i for i in sliced_func], func_obj.name, propagated_vars

    else:
        raise TypeError(
            f"[{Fore.RED}ERROR{Fore.RESET}] output_mode must be either OutputMode.Printed or OutputMode.Returned"
        )
