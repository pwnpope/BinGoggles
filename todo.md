# BinGoggles v1.0.1 TODO

## 📚 Documentation & Packaging
- [x] Finalize the README
- [ ] Review and enhance all docstrings
- [ ] Auto-generate documentation from docstrings (consider GitHub Pages)
- [ ] Document test cases in test/test_auxiliary.py
- [x] Publish on GitHub

## 🧪 Testing & Validation
- [ ] Expand tests for:
  - [ ] Imported functions
  - [x] Global variables
  - [x] Function parameter taint propagation

## 🧩 Taint Analysis Improvements
- [x] Determine if function return values are tainted
- [x] Add support for global variables
  - [x] Perform extensive globals testing
- [ ] Add support for imported functions
  - [x] Load libraries (supplied by user)
  - [x] Memoize imported function analysis to disk
  - [ ] Integrate imported function taint analysis into engine
- [ ] Improve is_function_param_tainted
  - [x] Fix false positive from result_name
  - [x] Fix false positive with x->d
  - [x] Map returned parameters to their respective tainted params
  - [x] Add recursion limit to prevent path explosion
  - [ ] Improve the function to account for more SSA MLIL operations

## 💡 Analysis Features
- [ ] Implement better memoization system (for general analysis)
- [x] Implement support for:
  - [x] MLIL_STORE_STRUCT
  - [x] MLIL_SET_VAR_FIELD
  - [x] Tracking specific struct members
- [x] Finish UAF and format string vulnerability detection
  - [x] Implement interprocedural analysis into UAF detection

## ⚙️ Refactors & Internal Improvements
- [x] Unify trace_forward() and trace_backward() argument structure
- [x] Properly handle libraries=None during initialization
- [ ] Rename vfa.py to bg.py for clarity
- [ ] Fix `get_struct_field_name` to handle nested field names
- [ ] Improve `is_function_param_tainted` to account for additional SSA MLIL operations

## 🎯 Usability
- [x] Add a Target class for defining analysis targets
- [ ] Binary Ninja Plugin


## VFG
- [ ] Variable Flow Graph (VFG)
- [ ] Simple non-DSA/SA constraint analysis in the VFG
- [ ] Write test cases for VFG generation
- [ ] Make sure the VFG knows the if statements and interproc stuff