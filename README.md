# `Bingoggles` The Assumed Taint Analysis Engine

![](images/bingoggles.jpeg)

- Variables are the key to storing data in programs, that's why when we do perform any kind of analysis as a vulnerability researcher we usually track what variables contain user input and start from there, my library will help with preforming analysis on these variables by providing through propagation analysis.

- In the development of my library I coined the term "complete slice" which means we're tainting the variable and tracking its usage throughout the entire program. What does this mean? This means that if data from a complete slice ends up in a sub-function call within the parent function we'll do analysis on that variable path as well.
    - In short we're gathering the full path of a variable.

## How is BinGoggles unique?
- Platform agnostic, working on linux, mac, and windows ✅ 
- Intraprocedural and interprocedural analysis ✅
- Library agnostic (kinda) ✅
    - User supplies what libraries if any the target program is using.
- Architecture and language agnostic (kinda) ✅
    - As long as the target program loads into binja.
- Works on all types of variables from `normal variables` to `struct members`, `globals`, and `function parameters` ✅
- Easy API with plenty of examples ✅
- Both backwards and forwards taint analysis ✅
- Great for embedded targets ✅
- Both hugsy headless and binja headless support ✅

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

- **Spread the word** — tweet about your favorite feature, share in Slack/Discord channels, or write a blog post.

Thank you for helping make BinGoggles better!