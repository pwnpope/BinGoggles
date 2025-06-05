# BinGoggles: The Assumed Taint Analysis Engine

<img src="images/bingoggles.jpeg" alt="BinGoggles" width="700"/>

BinGoggles is a static taint analysis framework for Binary Ninja. It tracks variable flow both *within* and *across* functions supporting full inter/intraprocedural slicing, including globals, structs, and function parameters.

Want to write your own analysis? Start with `bingoggles/modules.py` it shows how UAF detection was built using the core engine.

### What is a "Complete Slice"?
A **complete slice** traces a tainted variable's full journey through function calls, across boundaries, and deep into control/data paths. It's end-to-end propagation, made simple.

## How is BinGoggles Unique?
- [x] **Platform agnostic** – Runs on Linux, macOS, and Windows
- [x] **Intraprocedural and interprocedural analysis** – Track variable flow within and across functions
- [ ] **Library agnostic (mostly)** – User defines any external libraries for deeper analysis
    - work in progress
- [x] **Architecture/language agnostic (mostly)** – Works with any binary that loads into Binary Ninja
- [x] **Supports all variable types** – Local variables, struct members, globals, and function parameters
- [x] **Easy-to-use API** – Designed for extensibility with plenty of usage examples
- [x] **Bidirectional taint analysis** – Supports both forward and backward slicing
- [x] **Embedded-friendly** – Well-suited for firmware and embedded target analysis
- [x] **Headless compatible** – Supports both Hugsy’s and Binary Ninja’s headless modes

## Install
#### A) Setup python virtual environment
```bash
$ python3 -m venv .bg
$ source .bg/bin/activate
```

#### B) Install the requirements
```bash
$ pip install -r requirements.txt
# Install binaryninja API in the virtual environment
$ /path/to/binaryninja/scripts/linux-setup.sh
$ python3 setup.py install
$ pip install -e .
```

#### Using BinGoggles with [Hugsy Headless](https://github.com/hugsy/binja-headless)
- Before running this you obviously need to install and configure hugsy headless. 
```python
from bingoggles.bingoggles_types import *
from os import abspath

test_bin = "./test/binaries/bin/test_mlil_store"
bg_init = BGInitRpyc(
    target_bin=abspath(test_bin),
    libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
    host="127.0.0.1",
    port=18812,
)

bn, bv, libraries_mapped = bg_init.init()

analysis = Analysis(
    binaryview=bv, binaryninja=bn, verbose=True, libraries_mapped=libraries_mapped
)

analysis.tainted_slice(
    target=TaintTarget(0x00401212, "rdi"),
    var_type=SlicingID.FunctionVar,
)
```

#### Example usage (running a test case)
```bash
python3 -m pytest -s --rpyc test/test_auxiliary.py::test_global_tracking_fwd_var
```

## Generating Documentation
```bash
cd docs
make html
cd ..
xdg-open docs/build/html/index.html
```

## Contributions
- **Report issues**: If you encounter a bug or have a feature request, please open an issue so we can track and address it.

- **Submit pull requests**: Want to improve the code or documentation? Fork the repo, make your changes, and submit a pull request—PRs are reviewed on a regular basis.

- **Join the discussion**: Have questions or ideas? Drop a comment in issues or join our community channels to share your thoughts.

- **Spread the word** — Tweet about your favorite feature, share in Slack/Discord channels, or write a blog post.

Thank you for helping make BinGoggles better!
