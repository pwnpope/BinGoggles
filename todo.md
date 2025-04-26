# BinGoggles TODO

## 📚 Documentation & Packaging
- [ ] Finalize the README
- [ ] Improve and review all docstrings
- [ ] Auto-generate documentation from docstrings (consider GitHub Pages)
- [ ] Document test cases (`test_cases/` and `test_auxiliary`)
- [ ] Ship and publish on GitHub

## 🧩 Taint Analysis Improvements
- [x] Determine whether returned variables from functions are tainted
- [x] Add support for globals  
    - [ ] Perform extensive globals testing (in progress)
- [ ] Add support for imported functions  
    - [x] Load libraries (supplied by user)  
    - [x] Memoize imported function analysis to disk  
    - [ ] Integrate imported function taint analysis into engine
- [ ] Improve `is_function_param_tainted()`  
    - [x] Fix false positive from `result_name`
    - [x] Fix false positive with `x->d`
    - [ ] Map returned parameters to their respective tainted params
    - [ ] Add recursion limit to prevent deep explosion

## 💡 Analysis Features
- [ ] Implement better memoization system (for general analysis)
- [ ] Improve backwards taint analysis output
- [ ] Implement scanners 
    - [ ] Constraint analysis for the VFG
    - [ ] VFG (Variable Flow Graph)  
- [X] Implement support for:  
    - [X] `MLIL_STORE_STRUCT`
    - [ ] `MLIL_SET_VAR_FIELD`
    - [X] Tracking specific struct members
- [ ] Finish UAF (Use After Free) and format string vulnerability detection

## 🧪 Testing & Validation
- [ ] Extend tests for:
    - [ ] Imported functions
    - [X] Globals
    - [X] Function parameter taint propagation

## ⚙️ Refactors & Internal Improvements
- [x] Unify `trace_forward()` and `trace_backward()` argument structure
- [ ] Error handling:
    - [ ] Properly handle `libraries=None` during initialization

## 🎯 Usability
- [x] Add a `Target` class for defining analysis targets
- [ ] Design and implement plugin:
    - [ ] Binary Ninja Plugin **or** External GUI
