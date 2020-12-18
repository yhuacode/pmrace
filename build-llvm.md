### Overview

PMRace uses LLVM's [DataFlowSanitizer](https://clang.llvm.org/docs/DataFlowSanitizer.html) project to enable taint analysis to detect inconsistent PM writes based on reading unflushed. Due to the function wrapper (i.e., `dfs$`) introduced by DataFlowSanitizer, all libraries with memory access need to be instrumented, unless the library doesn't have impact on the consistency (e.g., `libPMRaceHook.so`). Therefore, we need instrument STL for C++ applications.

### Steps

The instructions only cover the necessary steps to instrument `libcxx` and `libcxxabi`. Details can be found in this [blog](https://mcopik.github.io/c++/2020/02/24/dataflow/).

1. Build LLVM from source.

```sh
    $ mkdir build
    $ cd build
    $ cmake -G 'Ninja' -DLLVM_ENABLE_PROJECTS='clang;clang-tools-extra;compiler-rt;libunwind;lld;lldb;polly;debuginfo-tests' -DCMAKE_INSTALL_PREFIX=/path/to/install/llvm -DCMAKE_BUILD_TYPE=Release ../llvm
    $ cmake --build . -j
    $ cmake --build . --target install
```

2. Build `libc++abi.a`.

```sh
    $ mkdir build-libcxxabi
    $ cd build-libcxxabi
    $ CC=clang CXX=clang++ cmake -G "Ninja" -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_INSTALL_PREFIX=/tmp/llvm-11-libcxxabi -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS=-fsanitize=dataflow -DCMAKE_CXX_FLAGS=-fsanitize=dataflow -DLLVM_PATH=/tmp/llvm-11 -DLIBCXXABI_ENABLE_SHARED=NO -DLIBCXXABI_LIBCXX_PATH=../libcxx ../libcxxabi
```

3. Build `libc++.a` and `libc++experimental.a`.

```sh
    $ mkdir build-libcxx
    $ cd build-libcxx
    $ CC=clang CXX=clang++ cmake -G "Ninja" -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_INSTALL_PREFIX=/tmp/llvm-11-libcxx -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS=-fsanitize=dataflow -DCMAKE_CXX_FLAGS=-fsanitize=dataflow -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_CXX_ABI=libcxxabi -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON -DLIBCXX_CXX_ABI_INCLUDE_PATHS=../libcxxabi/include/ -DLIBCXX_CXX_ABI_LIBRARY_PATH=../build-libcxxabi/lib/ ../libcxx
```

4. Merge the generated libs into the LLVM installation path in *Step 1*.