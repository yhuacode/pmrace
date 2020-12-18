#ifndef _PMRACE_EXTERNAL_CALL_H_
#define _PMRACE_EXTERNAL_CALL_H_

#include <vector>
#include <string>
#include <set>

using namespace std;

namespace PMRace {

    const vector<string> MEMCPY_CALLS {
        "llvm.memcpy.p0i8.p0i8.i32",
        "llvm.memcpy.p0i8.p0i8.i64",
        "llvm.memmove.p0i8.p0i8.i32",
        "llvm.memmove.p0i8.p0i8.i64"
    };

    const vector<string> MEMSET_CALLS {
        "llvm.memset.p0i8.i32",
        "llvm.memset.p0i8.i64",
    };

    const set<string> SIZE_32 {
        "llvm.memcpy.p0i8.p0i8.i32",
        "llvm.memmove.p0i8.p0i8.i32",
        "llvm.memset.p0i8.i32"
    };

    const set<string> SIZE_64 {
        "llvm.memcpy.p0i8.p0i8.i64",
        "llvm.memmove.p0i8.p0i8.i64",
        "llvm.memset.p0i8.i64"
    };

} /* namespace pmrace */

#endif // _PMRACE_EXTERNAL_CALL_H_