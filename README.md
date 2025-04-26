## Introducing `Bingoggles` the assumed taint analysis engine

- Variables are the key to storing data in programs, that's why when we do perform any kind of analysis as a vulnerability researcher we usually track what variables contain user input and start from there, my library will help with preforming analysis on these variables providing through propagation analysis.

- In the development of my library I coined the term "complete slice" which means we're tainting the variable and tracking its usage throughout the entire program. What does this mean? This means that if data from a complete slice ends up in a sub-function call within the parent function we'll do analysis on that variable path as well.
    - In short we're gathering the full path of a variable.


![](images/bingoggles.png)

## How is BinGoggles unique?
- Platform agnostic, working on linux, mac, and windows ✅ 
- Intraprocedural and interprocedural analysis ✅
- Library agnostic (kinda) ✅
    - User supplies what libraries if any the target program is using.
- Architecture and language agnostic (kinda) ✅
    - As long as the target program loads into binja.
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

analysis.tainted_forward_slice(
    target=TaintTarget(0x00401212, "rdi"),
    var_type=SlicingID.FunctionVar,
    output=OutputMode.Printed,
)

```

#### Running test cases
```bash
python3 -m pytest -s --rpyc test/test_auxiliary.py::test_global_tracking_fwd_var
```
