### Requirements

Install the following dependencies on Ubuntu 18.04 (or above).

```sh
        $ sudo apt-get install build-essential autoconf pkg-config \
                git python3 python3-dev \
                m4 pandoc libndctl-dev libdaxctl-dev \
                libelf-dev elfutils libdw-dev libunwind-dev
```

Additional notes:

- `m4`, `pandoc`, `libndctl-dev` (v63 or later) and `libdaxctl-dev` (v63 or later) are required for `pmdk`
- `libelf-dev`, `elfutils`, `libdw-dev`, `libunwind-dev` are required for stack traces (i.e., `libdw` and `libunwind`)


### Configure

Update submodules (i.e., PMDK)

```sh
        $ git submodule init && git submodule update --progress
```

Apply the attached patch for PMDK.

```sh
        $ cd ./deps/pmdk
        $ git apply ../../patches/pmdk.diff
```

There are some enviroument variables to be set.

```sh
        $ export PMEM_IS_PMEM_FORCE=1
        $ export LLVM_DIR=/path/to/llvm-11-install-dir
        $ export PATH=$LLVM_DIR/bin:$PATH
        $ export PMRACE_DIR=/path/to/pmrace
```


### Build

1. Change directory to "instrument"

```sh
        $ cd $PMRACE_DIR/instrument
```

2. Build the pass and `hook_ctr_cli`

```sh
        $ make
```

3. Build PMDK using PMRace

```sh
        $ make pmdk
```
