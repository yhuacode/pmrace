// stack_trace.c
// from https://gist.github.com/banthar/1343977

// dependencies: libelf-dev elfutils libdw-dev libunwind-dev
// ldflags: -ldw -lunwind -g

#ifndef _PMRACE_HOOK_TRACE_H_
#define _PMRACE_HOOK_TRACE_H_

#define UNW_LOCAL_ONLY

#include <elfutils/libdwfl.h>
#include <libunwind.h>
#include <sanitizer/dfsan_interface.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "hook_common.h"


void __attribute__((noinline)) printStackTrace(FILE* out, int skip);

#endif // _PMRACE_HOOK_TRACE_H_