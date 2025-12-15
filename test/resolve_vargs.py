from bingoggles import *
import binaryninja


def get_all_files(directory):
    """
    Recursively gets the full path for every file in a given directory
    and its subdirectories.
    """
    file_paths = []
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' does not exist or is not a directory.")
        return []

    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            file_paths.append(full_path)

    return file_paths


for file in get_all_files("binaries/bin"):
    bv = binaryninja.load(file)
    VargFunctionCallResolver(bv).resolve_varg_func_calls()
