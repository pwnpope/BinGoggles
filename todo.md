# BinGoggles v1.0.0 TODO

## 📚 Documentation & Packaging
- [X] Finalize the README
- [ ] Improve and review all docstrings
- [ ] Auto-generate documentation from docstrings (consider GitHub Pages)
- [ ] Document test cases (`test_cases/` and `test_auxiliary`)
- [X] Ship and publish on GitHub

## 🧩 Taint Analysis Improvements
- [x] Determine whether returned variables from functions are tainted
- [x] Add support for globals  
    - [X] Perform extensive globals testing
- [ ] Add support for imported functions  
    - [x] Load libraries (supplied by user)  
    - [x] Memoize imported function analysis to disk  
    - [ ] Integrate imported function taint analysis into engine
- [ ] Improve `is_function_param_tainted()`  
    - [x] Fix false positive from `result_name`
    - [x] Fix false positive with `x->d`
    - [X] Map returned parameters to their respective tainted params
    - [X] Add recursion limit to prevent path explosion
    - [ ] Improve the function to account for more SSA MLIL operations  <- Currently working on this so that it can successfully complete the test case for `python3 -m pytest -s --rpyc test/test_auxiliary.py::test_is_param_tainted`

## 💡 Analysis Features
- [ ] Implement better memoization system (for general analysis)
- [ ] VFG (Variable Flow Graph)
- [ ] (simple non DSA/SA) Constraint analysis in the VFG

- [X] Implement support for:  
    - [X] `MLIL_STORE_STRUCT`
    - [ ] `MLIL_SET_VAR_FIELD`
    - [X] Tracking specific struct members
- [ ] Finish UAF (Use After Free) and format string vulnerability detection
    - [ ] Implement interprocederal analysis into the current UAF detection stuff


## 🧪 Testing & Validation
- [ ] Extend tests for:
    - [ ] Imported functions
    - [X] Globals
    - [X] Function parameter taint propagation

## ⚙️ Refactors & Internal Improvements
- [x] Unify `trace_forward()` and `trace_backward()` argument structure
- [X] Error handling:
    - [X] Properly handle `libraries=None` during initialization

## 🎯 Usability
- [x] Add a `Target` class for defining analysis targets
- [ ] Binary Ninja Plugin