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

    Args:
        headers (list): List of column headers
        rows (list): List of rows, where each row is a list of cell values
        min_widths (list, optional): Minimum width for each column
        max_widths (list, optional): Maximum width for each column

    Returns:
        list: List of strings representing the formatted table
    """
    if not min_widths:
        min_widths = [3] * len(headers)
    if not max_widths:
        max_widths = [30] * len(headers)

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], min(max_widths[i], len(str(cell))))

    def wrap_text(text, width, col_idx):
        if col_idx == 2 and "(" in text and ")" in text:
            func_name, params = text.split("(", 1)
            params = params.rstrip(")")
            param_list = params.split(", ")

            if len(text) <= width:
                return [text]

            result = [func_name + "("]
            current_line = "  " + param_list[0]

            for param in param_list[1:]:
                if len(current_line + ", " + param) <= width - 2:
                    current_line += ", " + param
                else:
                    result.append(current_line)
                    current_line = "  " + param

            result.append(current_line + ")")
            return result
        else:
            wrapped = textwrap.wrap(text, width=width) or [""]
            return wrapped

    wrapped_rows = []
    for row in rows:
        wrapped_row = []
        for i, cell in enumerate(row):
            wrapped_row.append(wrap_text(str(cell), col_widths[i], i))
        wrapped_rows.append(wrapped_row)

    table_lines = []

    top_border = "┌" + "┬".join("─" * w for w in col_widths) + "┐"
    table_lines.append(top_border)

    header_line = "│"
    for i, header in enumerate(headers):
        header_line += f" {header:<{col_widths[i]}} │"
    table_lines.append(header_line)

    separator = "├" + "┼".join("─" * w for w in col_widths) + "┤"
    table_lines.append(separator)

    for wrapped_row in wrapped_rows:
        max_lines = max(len(cell) for cell in wrapped_row)

        for line_idx in range(max_lines):
            row_line = "│"
            for i, cell_lines in enumerate(wrapped_row):
                cell_content = (
                    cell_lines[line_idx] if line_idx < len(cell_lines) else ""
                )
                row_line += f" {cell_content:<{col_widths[i]}} │"
            table_lines.append(row_line)

    bottom_border = "└" + "┴".join("─" * w for w in col_widths) + "┘"
    table_lines.append(bottom_border)

    return table_lines


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
    Dynamically adjusts column widths and wraps cell content if necessary.

    Args:
        path_data (List): A list of objects representing taint analysis path data, each expected to have
                          a 'loc.instr_index' attribute and a string representation that can be parsed.

    Note:
        The global variables USE_COLOR and LOG_FILE can be set through set_output_options() to control
        whether colorized output is used and to optionally log the output to a file.
    """
    raw_rows = []
    color_rows = []

    for bingoggles_data in path_data:
        instr_index = str(bingoggles_data.loc.instr_index)
        split_loc = str(bingoggles_data).split(" ")
        loc_data = list(takewhile(lambda x: x != "->", split_loc))
        loc_address = loc_data.pop(0)
        loc = "".join(loc_data)
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
            colorize(formatted_loc, Fore.GREEN),
            colorize(tainted_var, Fore.MAGENTA),
            colorize(propagated_var, Fore.BLUE),
            conf_col,
        ]
        color_rows.append(color_row)

    col_titles = [
        "Idx",
        "Address",
        "LOC",
        "Target Var",
        "Propagated Var",
        "Taint Confidence",
    ]

    min_widths = [5, 12, 27, 12, 16, 18]
    max_widths = [8, 14, 40, 16, 20, 20]

    for i in range(len(min_widths)):
        max_widths[i] = max(max_widths[i], min_widths[i])

    col_widths = [max(len(title), min_widths[i]) for i, title in enumerate(col_titles)]
    for row in raw_rows:
        for i, cell in enumerate(row):
            cell_width = len(str(cell))
            col_widths[i] = max(col_widths[i], min(max_widths[i], cell_width))

    wrapped_rows = []
    for raw_row in raw_rows:
        wrapped_row = []
        for i, cell in enumerate(raw_row):
            if i == 2:
                if "(" in str(cell) and ")" in str(cell):
                    func_name, params = str(cell).split("(", 1)
                    params = params.rstrip(")")
                    param_list = params.split(", ")

                    if len(str(cell)) <= col_widths[i]:
                        lines = [str(cell)]
                    else:
                        lines = [func_name + "("]
                        current_line = "  " + param_list[0]

                        for param in param_list[1:]:
                            if len(current_line + ", " + param) <= col_widths[i] - 2:
                                current_line += ", " + param
                            else:
                                lines.append(current_line)
                                current_line = "  " + param

                        lines.append(current_line + ")")
                else:
                    lines = textwrap.wrap(str(cell), width=col_widths[i]) or [""]
            else:
                lines = textwrap.wrap(str(cell), width=col_widths[i]) or [""]

            wrapped_row.append(lines)
        wrapped_rows.append(wrapped_row)

    for wrapped_row in wrapped_rows:
        for i, lines in enumerate(wrapped_row):
            for line in lines:
                col_widths[i] = max(col_widths[i], min(max_widths[i], len(line)))

    colorized_rows = []
    for wrapped_row, color_row in zip(wrapped_rows, color_rows):
        colorized_wrapped_row = []

        for i, (cell_lines, colored_cell) in enumerate(zip(wrapped_row, color_row)):
            if colored_cell.startswith("\x1b"):
                color_code = colored_cell[: colored_cell.find("m") + 1]
                content = re.sub(r"\x1b\[[0-9;]*m", "", colored_cell)
                reset_code = Fore.RESET

                colorized_lines = []
                for j, line in enumerate(cell_lines):
                    if i < 2 and j > 0:
                        colorized_lines.append("")
                    else:
                        colorized_lines.append(f"{color_code}{line}{reset_code}")
            else:
                colorized_lines = []
                for j, line in enumerate(cell_lines):
                    if i < 2 and j > 0:
                        colorized_lines.append("")
                    else:
                        colorized_lines.append(line)

            colorized_wrapped_row.append(colorized_lines)

        colorized_rows.append(colorized_wrapped_row)

    row_heights = []
    for wrapped_row in wrapped_rows:
        max_lines = max(len(cell_lines) for cell_lines in wrapped_row)
        row_heights.append(max_lines)

    def make_border(char_left, char_mid, char_right, char_fill):
        parts = []
        border_color = Fore.LIGHTBLACK_EX if USE_COLOR else ""
        reset = Fore.RESET if USE_COLOR else ""

        parts.append(border_color + char_left)

        for i, width in enumerate(col_widths):
            parts.append(char_fill * (width + 2))  # +2 for padding spaces
            if i < len(col_widths) - 1:
                parts.append(char_mid)

        parts.append(char_right + reset)
        return "".join(parts)

    top = make_border("┌", "┬", "┐", "─")

    header = []
    border_color = Fore.LIGHTBLACK_EX if USE_COLOR else ""
    reset = Fore.RESET if USE_COLOR else ""
    header.append(border_color + "│" + reset)

    for i, title in enumerate(col_titles):
        header.append(" ")
        header.append(colorize(title, Fore.YELLOW))
        padding = " " * (col_widths[i] - len(title) + 1)  # +1 for right padding
        header.append(padding)
        header.append(f"{border_color}│{reset}")

    header_line = "".join(header)

    sep = make_border("├", "┼", "┤", "─")

    # Print and log top border
    print(top)
    log_output(top)

    # Print and log header
    print(header_line)
    log_output(header_line)

    # Print and log separator
    print(sep)
    log_output(sep)

    for row_idx, (colorized_row, row_height) in enumerate(
        zip(colorized_rows, row_heights)
    ):
        for line_idx in range(row_height):
            row_parts = []
            border_color = Fore.LIGHTBLACK_EX if USE_COLOR else ""
            reset = Fore.RESET if USE_COLOR else ""
            row_parts.append(border_color + "│" + reset)

            for col_idx, cell_lines in enumerate(colorized_row):
                if line_idx < len(cell_lines):
                    cell_line = cell_lines[line_idx]
                else:
                    cell_line = ""

                visible_len = len(re.sub(r"\x1b\[[0-9;]*m", "", cell_line))

                row_parts.append(" ")
                row_parts.append(cell_line)
                padding = " " * max(
                    0, col_widths[col_idx] - visible_len + 1
                )  # +1 for right padding
                row_parts.append(padding)
                row_parts.append(f"{border_color}│{reset}")

            row_line = "".join(row_parts)
            print(row_line)
            log_output(row_line)

    # Print and log bottom border
    bot = make_border("└", "┴", "┘", "─")
    print(bot)
    log_output(bot)


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
