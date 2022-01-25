### Description

PMRace is a fuzz testing tool to efficiently detect persistent memory (PM) concurrency bugs hidden in thread interleavings. For more details, please refer to our paper:

- Zhangyu Chen, Yu Hua, Yongle Zhang, Luochangqi Ding, "Efficiently Detecting Concurrency Bugs in Persistent Memory Programs", Proceedings of the 27th ACM International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS), 2022.

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

2. Build the LLVM pass and `hook_ctr_cli`

```sh
        $ make
```

3. Build PMDK using PMRace

```sh
        $ make pmdk
```

### Use

Here are some [examples](https://github.com/yhuacode/pm-workloads) for the use of PMRace to debug PM programs. We have constructed and released [artifacts](https://github.com/yhuacode/pmrace-vagrant) for public use.

## Contact

If you have any problems, please report in the issue page or contact me.

- Zhangyu Chen (chenzy@hust.edu.cn)
