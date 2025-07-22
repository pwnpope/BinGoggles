import binaryninja
import os


def save_bin_to_bndb(input_file_path: str, output_bndb_path: str):
    """
    Opens a binary file, performs analysis, and saves it to a .bndb file.

    Args:
        input_file_path (str): The path to the input binary file.
        output_bndb_path (str): The desired path for the output .bndb file.
    """
    bv = binaryninja.load(input_file_path)

    if bv is None:
        print(f"Error: Could not open file {input_file_path}")
        return

    print(f"Opened {input_file_path}. Starting analysis...")

    bv.update_analysis_and_wait()
    print("Analysis complete.")

    if not output_bndb_path.lower().endswith(".bndb"):
        output_bndb_path += ".bndb"

    success = bv.file.create_database(output_bndb_path)

    if success:
        print(f"Successfully saved analysis to {output_bndb_path}")
    else:
        print(f"Error: Failed to save analysis to {output_bndb_path}")


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


if __name__ == "__main__":
    for file in get_all_files("binaries/bin"):
        directory_part, file_basename = os.path.split(file)
        file_name_without_ext, _ = os.path.splitext(file_basename)
        modified_name = os.path.join(directory_part, file_name_without_ext) + ".bndb"
        save_bin_to_bndb(file, modified_name)
        print(f"Processed {file} -> {modified_name}")
    print("Done processing all files.")
