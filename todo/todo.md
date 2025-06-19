# BinGoggles TODO

## 📚 Documentation & Packaging
- [x] Documentation
- [x] Write valid assertions in test/test_cases.py
- [ ] Set up server with a subdomain for bingoggles documentation

## 🧩 Taint Analysis Improvements
- [ ] Add support for imported functions
  - [ ] Integrate imported function taint analysis into engine
- [ ] Improve `trace_function_taint`
  - [x] Improve the function to account for more SSA MLIL operations
  - [ ] Memoize results
    <!--
        __builtin_memcpy(dest, src, n)
        __builtin_memset(s, c, n)
        __builtin_strcpy(dest, src)
        __builtin_strncpy(dest, src, n)
        __builtin_wcscpy(dest, src)
    -->

## 💡 Analysis Features
- [ ] Implement better memoization system (for general analysis)

## ⚙️ Refactors & Internal Improvements
- [x] Rename vfa.py to bg.py for clarity
- [x] Fix `get_struct_field_name` to handle nested field names
- [ ] Improve the speed of the global and struct member analysis if possible

## 🎯 Usability
- [x] Add a Target class for defining analysis targets

## VFG
- [ ] Variable Flow Graph (VFG) in the form of a Directed acyclic graph (DAG)
- [ ] Simple non-DSA/SA constraint analysis in the VFG
- [ ] Write test cases for VFG generation
- [ ] Make sure the VFG represents the if statements and interproc stuff

## Modules
- [ ] UAF: implement varias alloc functions to get their respective size param and see if the size is reallocated, see modules.py for more info and look for `TODO`
  - [ ] allocator like function identification
  - [ ] caching both allocator and deallocating functions for any continued analysis or repeated analysis