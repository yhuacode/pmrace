#ifndef _PMRACE_INSTRUMENT_HOOK_BITMAP_H_
#define _PMRACE_INSTRUMENT_HOOK_BITMAP_H_

/* BITMAP */
//
// An implementation of bitmap based on Linux kernel 4.13-rc3
//
// Reference:
// 1. https://0xax.gitbooks.io/linux-insides/content/DataStructures/linux-datastructures-3.html
// 2. https://github.com/torvalds/linux/tree/16f73eb02d7e1765ccab3d2018e0bd98eb93d973


#include "hook_common.h"


#define DECLARE_BITMAP(name,bits) \
  unsigned long name[BITS_TO_LONGS(bits)]

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))


/* BITMAP API */
#define LOCK_PREFIX "\n\tlock; "
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.
 */
static inline void set_bit(long nr, volatile unsigned long *addr) {
  asm volatile(LOCK_PREFIX "bts %1,%0"
    : BITOP_ADDR(addr) : "Ir" (nr) : "memory");
}


/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
 * in order to ensure changes are visible on other processors.
 */
static inline void clear_bit(long nr, volatile unsigned long *addr) {
  asm volatile(LOCK_PREFIX "btr %1,%0"
    : BITOP_ADDR(addr) : "Ir" (nr) : "memory");
}

// Recent compilers (e.g., >= gcc-6) should support condition flags
//  https://stackoverflow.com/questions/30314907/using-condition-flags-as-gnu-c-inline-asm-outputs
#define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
#define CC_OUT(c) "=@cc" #c


/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(long nr, volatile const unsigned long *addr) {
  int oldbit;
  asm volatile("bt %2,%1\n\t"
                CC_SET(c)
                : CC_OUT(c) (oldbit)
                : "m" (*(unsigned long *)addr), "Ir" (nr));
  return oldbit;
}
/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_set_bit(long nr, volatile unsigned long *addr) {
// The implementation is based on
// https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/rmwcc.h

  int oldbit;
  asm volatile(LOCK_PREFIX "bts %2,%0"
               CC_SET(c)
               : "+m" (*addr), CC_OUT(c)(oldbit)
               : "Ir" (nr) : "memory");
  return oldbit;
}

/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word) {
  asm("rep; bsf %1,%0"
    : "=r" (word)
    : "rm" (word));
  return word;
}

/*
 * Find the first set bit in a memory region.
 */
static inline unsigned long find_first_bit(
  const unsigned long *addr, unsigned long size) {
  unsigned long idx;

  for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
    if (addr[idx])
      return min(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
  }

  return size;
}

/*
 * Find the next set bit in a memory region.
 */
static inline unsigned long find_next_bit(
  const unsigned long *addr, unsigned long nbits, unsigned long start) {
  unsigned long invert = 0UL;
  unsigned long tmp;

	if (unlikely(start >= nbits))
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return min(start + __ffs(tmp), nbits);
}

#define LOCKED      1
#define UNLOCKED    0

static inline void __wait_until_free(
  long nr, volatile unsigned long *addr) {
  while (test_bit(nr, addr) == LOCKED) {
    asm ("pause");
  }
}

/*
 * Acquire a spinlock.
 */
static inline void lock_bit(long nr, volatile unsigned long *addr) {
  do {
    __wait_until_free(nr, addr);
  } while (test_and_set_bit(nr, addr) == LOCKED);
}

/*
 * Release a spinlock.
 */
static inline void unlock_bit(long nr, volatile unsigned long *addr) {
  clear_bit(nr, addr);
}

#endif // _PMRACE_INSTRUMENT_HOOK_BITMAP_H_