### Requirements

There are two classes of dependencies: **basic** and **optional** dependencies.
**Basic dependencies** are `libndctl-dev` (v63 or later) and `libdaxctl-dev` (v63 or later).
**Optional dependencies** are `libelf-dev`, `elfutils`, `libdw-dev` and `libunwind-dev`.

Install the following packages for basic and optional dependencies on Ubuntu 18.04 (or above).

```sh
        $ sudo apt-get install build-essential autoconf pkg-config \
                git python3 python3-dev \
                m4 pandoc libndctl-dev libdaxctl-dev \
                libelf-dev elfutils libdw-dev libunwind-dev
```

For basic dependencies only, run the following command.

```sh
        $ sudo apt-get install build-essential autoconf pkg-config \
                git python3 python3-dev \
                m4 pandoc libndctl-dev libdaxctl-dev
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

**NOTE**: There are many enviroumental variables to be set. Please source the `env.sh` in the root folder of this repository. If `env.sh` does not exist, contact the developers. A typical command to setup the environmental variables is as follows.

```sh
        $ cd /path/to/pmrace
        $ source ./env.sh
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

Build without stack traces enabled (due to the lack of `libdw` and `libunwind`)

```sh
        $ make BUILD_STACK_TRACE=n              # disable optional stack trace
```

3. Build and instrument the dependencies (i.e., PMDK) for testing

```sh
        $ cd $PMRACE_DIR/tests
        $ make
```
