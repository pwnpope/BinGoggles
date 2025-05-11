# BinGoggles v.0.3 TODO

## 📚 Documentation & Packaging
- [ ] Review and enhance all docstrings after finishing 0.0.3
- [x] Write valid assertions in test/test_cases.py

## 🧪 Testing & Validation
- [ ] Expand tests for:
  - [ ] Imported functions

## 🧩 Taint Analysis Improvements
- [ ] Add support for imported functions
  - [ ] Integrate imported function taint analysis into engine
- [ ] Improve is_function_param_tainted
  - [ ] Improve the function to account for more SSA MLIL operations

## 💡 Analysis Features
- [ ] Implement better memoization system (for general analysis)

## ⚙️ Refactors & Internal Improvements
- [x] Rename vfa.py to bg.py for clarity
- [ ] Fix `get_struct_field_name` to handle nested field names
- [ ] Improve `is_function_param_tainted` to account for additional SSA MLIL operations
- [ ] Improve the speed of the global and struct member analysis if possible

## 🎯 Usability
- [x] Add a Target class for defining analysis targets
- [ ] Binary Ninja Plugin

## VFG
- [ ] Variable Flow Graph (VFG)
- [ ] Simple non-DSA/SA constraint analysis in the VFG
- [ ] Write test cases for VFG generation
- [ ] Make sure the VFG knows the if statements and interproc stuff