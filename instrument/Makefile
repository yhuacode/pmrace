all: libPMRacePass.so hook_ctr_cli libPMRaceHook.so

CXX=$(LLVM_DIR)/bin/clang++
CC=$(LLVM_DIR)/bin/clang
LLVM_CONFIG=$(LLVM_DIR)/bin/llvm-config

# We remove the "-fno-exceptions" for json library
# LIBPASSFLAGS=`$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fPIC
LIBPASSFLAGS= -I$(LLVM_DIR)/include -std=c++14 -fno-rtti -D_GNU_SOURCE -D_DEBUG -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -Wl,-znodelete -fPIC

# PMRACEPASS_FLAGS= -Xclang -load -Xclang ./libPMRacePass.so

libPMRacePass.so : main.cpp instrument.cpp
	$(CXX) $(LIBPASSFLAGS) $^ -o $@ `$(LLVM_CONFIG) --ldflags` -shared

DEBUGFLAGS= -g -mllvm -dfsan-abilist=pmrace-ABI.txt

ifneq ($(BUILD_STACK_TRACE),n)
	HOOK_EXTRA_FLAGS += -DSTACK_TRACE_ENABLE=1
	HOOK_EXTRA_LDFLAGS += -ldw -L/usr/lib/x86_64-linux-gnu/ -lunwind
	HOOK_EXTRA_OBJS += hook_trace.o
endif

CFLAGS=$(DEBUGFLAGS) $(HOOK_EXTRA_FLAGS) -MMD
LDFLAGS=$(HOOK_EXTRA_LDFLAGS)

# for PMDK
NPROCS = $(grep -c ^processor /proc/cpuinfo)
MKFILE_PATH = $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR = $(dir $(MKFILE_PATH))
TOP_DIR = $(abspath $(MKFILE_DIR)..)
PMDK_DIR = $(abspath ../deps/pmdk)
PMDK_INSTALL_DIR = $(PMDK_DIR)/install


hook_ctrl.o: hook_ctrl.c
	$(CC) $(CFLAGS) -c -fPIC -fsanitize=dataflow $<

ifneq ($(BUILD_STACK_TRACE),n)
hook_trace.o: hook_trace.c
	$(CC) $(CFLAGS) -c -fPIC $<
endif

hook.o: hook.c
	$(CC) $(CFLAGS) -c -fPIC -fsanitize=dataflow $<

hook_validate.o: hook_validate.c
	$(CC) $(CFLAGS) -c -fPIC -fsanitize=dataflow $<

-include hook_ctrl.d hook_trace.d hook.d hook_validate.d

libPMRaceHook-PreFailure.so: hook.o hook_ctrl.o $(HOOK_EXTRA_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -shared -L$(LLVM_DIR)/lib -fsanitize=dataflow

libPMRaceHook-PostFailure.so: hook_validate.o hook_ctrl.o $(HOOK_EXTRA_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -shared -L$(LLVM_DIR)/lib -fsanitize=dataflow

libPMRaceHook.so: libPMRaceHook-PreFailure.so libPMRaceHook-PostFailure.so
	cp -f libPMRaceHook-PreFailure.so $@

hook_ctr_cli: hook_ctr_cli.c hook_ctrl.c $(HOOK_EXTRA_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

validate: libPMRaceHook-PostFailure.so
	cp -f libPMRaceHook-PostFailure.so libPMRaceHook.so


pmdk:
	@echo "MKFILE_DIR: $(MKFILE_DIR)"
	@echo "TOP_DIR: $(TOP_DIR)"
	@echo  "NPROCS: $(NPROCS)"
	@if [ -d "$(PMDK_INSTALL_DIR)" ]; then \
		echo "pmdk is already installed" && exit 1; \
	fi
	cp ../instrument/user.mk $(PMDK_DIR)
	make DEBUG=1 BUILD_EXAMPLES=n BUILD_BENCHMARKS=n BUILD_RPMEM=n NDCTL_ENABLE=n AVX512F_AVAILABLE=n -C $(PMDK_DIR) -j$(NPROCS)
	make DEBUG=1 BUILD_EXAMPLES=n BUILD_BENCHMARKS=n BUILD_RPMEM=n NDCTL_ENABLE=n AVX512F_AVAILABLE=n -C $(PMDK_DIR) -j$(NPROCS) install prefix=$(PMDK_INSTALL_DIR)


clean:
	rm -f libPMRacePass.so libPMRaceHook.so libPMRaceHook-PreFailure.so libPMRaceHook-PostFailure.so hook_ctr_cli *.o *.d

.PHONY: all clean validate
