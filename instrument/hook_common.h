#ifndef _PMRACE_INSTRUMENT_HOOK_COMMON_H_
#define _PMRACE_INSTRUMENT_HOOK_COMMON_H_


#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

typedef pid_t pid_32_t;
typedef uint64_t hval_64_t;

#define BITS_PER_BYTE 8
#define BITS_PER_LONG (BITS_PER_BYTE * sizeof(long))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_LONG)

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

#ifdef __GNUC__
# define likely(x)       __builtin_expect(!!(x), 1)
# define unlikely(x)     __builtin_expect(!!(x), 0)
#else
# define likely(x)       (x)
# define unlikely(x)     (x)
#endif

#define HOOK_DEBUG 1

#define debug(fmt, ...) \
    do { \
      if (HOOK_DEBUG) { \
        fprintf(stderr, "(hook-debug in [%s:%d:%s]) " fmt, \
          __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
      } \
    } while (0)\


static inline pid_32_t get_thread_id() {
  return syscall(SYS_gettid);
}


#endif // _PMRACE_INSTRUMENT_HOOK_COMMON_H_