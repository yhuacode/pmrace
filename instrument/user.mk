CXX=$(LLVM_DIR)/bin/clang++
CC=$(LLVM_DIR)/bin/clang

# USER_MK_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INSTRUMENT_PASS_DIR = $(abspath $(TOP)/../../instrument)

PMRACEPASS_FLAGS = -mclflushopt -mclwb -Xclang -load -Xclang $(INSTRUMENT_PASS_DIR)/libPMRacePass.so -fsanitize=dataflow -mllvm -dfsan-abilist=$(INSTRUMENT_PASS_DIR)/pmrace-ABI.txt
RACE_OUTPUT_FLAGS = -mllvm -coverage-path -mllvm output/cov -mllvm -race-path -mllvm output/race.csv -mllvm -unflushed-path -mllvm output/unflushed.csv -mllvm -meta-path -mllvm $@.json
RACE_PMDK_MODE_FLAGS = -mllvm -pmrace-mode -mllvm pmdk
DEBUGFLAGS = -g -O0

EXTRA_CFLAGS = $(PMRACEPASS_FLAGS) $(RACE_OUTPUT_FLAGS) $(RACE_PMDK_MODE_FLAGS) $(DEBUGFLAGS)
EXTRA_LDFLAGS = -L$(INSTRUMENT_PASS_DIR) -Wl,-rpath='$(INSTRUMENT_PASS_DIR)' -lPMRaceHook -fsanitize=dataflow
