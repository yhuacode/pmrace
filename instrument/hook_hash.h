#ifndef _PMRACE_INSTRUMENT_HOOK_HASH_H_
#define _PMRACE_INSTRUMENT_HOOK_HASH_H_


#include <linux/types.h>
#include <stdatomic.h>
#include <assert.h>

#include "hook_common.h"
#include "hook_bitmap.h"

// From linux kernel source code "linux/hash.h"
// https://elixir.bootlin.com/linux/v5.10.1/source/include/linux/hash.h
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline uint32_t hash_64(uint64_t val, unsigned int bits)
{
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return (val * GOLDEN_RATIO_64) >> (64 - bits);
}

static inline uint32_t hash_32(uint32_t val, unsigned int bits)
{
    // High bits are more random, so use them.
    return (val * GOLDEN_RATIO_32) >> (32 - bits);
}

/* utils */
#define _CANTOR_PAIR(n, m)          ((n) + (m)) * ((n) + (m) + 1) / 2 + (m)

typedef uint32_t hash24_t;
typedef uint16_t hash16_t;

static inline hash24_t hash_u64_into_h24(uint64_t n) {
    return (hash24_t)hash_64(n, 24);
}

static inline hash24_t hash_u64_into_h24_chain(uint64_t n, uint64_t m) {
    return hash_u64_into_h24(_CANTOR_PAIR(n, m));
}

static inline hash24_t hash_triple_u64_into_h24(uint64_t x, uint64_t y, uint64_t z) {
    return hash_u64_into_h24(_CANTOR_PAIR(_CANTOR_PAIR(x, y), z));
}

static inline hash16_t hash_u32_into_h16(uint64_t n) {
    return (hash16_t)hash_32(n, 16);
}


/* hash tables */
#define atomic32_t atomic_uint
#define atomic32_read atomic_load
#define atomic32_set atomic_store

#define atomic64_t atomic_ulong
#define atomic64_read atomic_load
#define atomic64_set atomic_store

// typedef void (*ht_##name ## _cb_func_type)( \
//             uint##klen ## _t key, struct name *val, void *arg \
//         )\

// void (*func)( \
//                 uint##klen ## _t key, struct name *val, void *arg \
//             ), \

#define HOOK_HMAP_DEFINE(name, bits, klen) \
        /* typedef */ \
        typedef void (*ht_##name ## _func_type)( \
            uint##klen ## _t key, struct name *val, void *arg \
        );\
        typedef struct __ht_##name { \
            DECLARE_BITMAP(bmap, (1 << bits)); \
            DECLARE_BITMAP(mtx, (1 << bits)); \
            struct  __htcell_##name { \
                atomic##klen ## _t key; \
                struct name val; \
            } cell[1 << bits]; \
        } ht_##name ## _t; \
        \
        /* functions */ \
        static inline struct name * \
        ht_##name ## _get_slot( \
            struct __ht_##name *ht, \
            uint##klen ## _t k, \
            ht_##name ## _func_type func, \
            void *arg \
        ) { \
            uint##klen ## _t e; \
            hash##bits ## _t i = hash_u##klen ## _into_h##bits(k); \
            hash##bits ## _t o = 0; \
            \
            while (test_and_set_bit(i, ht->bmap)) { \
                /* in case someone acquired the bit but has not set it yet */ \
                do { \
                    e = atomic##klen ## _read(&(ht->cell[i].key)); \
                } while (!e); \
                \
                /* check existence */ \
                if (e == k) { \
                    if (func) { \
                        /* atomically modify the slot value */ \
                        lock_bit(i, ht->mtx); \
                        func( \
                            atomic##klen ## _read(&(ht->cell[i].key)), \
                            &ht->cell[i].val, \
                            arg \
                        ); \
                        unlock_bit(i, ht->mtx); \
                    } \
                    return &(ht->cell[i].val); \
                } \
                \
                /* move on */ \
                i = (i + 1) % (1 << bits); \
                assert((++o) != ((1 << bits) - 1)); \
            } \
            \
            /* we are the first to set the bit */ \
            if (func) { \
                /* since the key is not set, we can skip locking */ \
                func( \
                    0, \
                    &ht->cell[i].val, \
                    arg \
                ); \
            } \
            atomic##klen ## _set(&(ht->cell[i].key), k); \
            return &(ht->cell[i].val); \
        } \
        \
        static inline struct name * \
        ht_##name ## _has_slot( \
            struct __ht_##name *ht, \
            uint##klen ## _t k, \
            ht_##name ## _func_type func, \
            void *arg \
        ) { \
            uint##klen ## _t e; \
            hash##bits ## _t i = hash_u##klen ## _into_h##bits(k); \
            hash##bits ## _t o = 0; \
            \
            while (test_bit(i, ht->bmap)) { \
                /* in case someone acquired the bit but has not set it yet */ \
                do { \
                    e = atomic##klen ## _read(&(ht->cell[i].key)); \
                } while (!e); \
                \
                /* check existence */ \
                if (e == k) { \
                    if (func) { \
                        lock_bit(i, ht->mtx); \
                        func( \
                            atomic##klen ## _read(&(ht->cell[i].key)), \
                            &ht->cell[i].val, \
                            arg \
                        ); \
                        unlock_bit(i, ht->mtx); \
                    } \
                    return &(ht->cell[i].val); \
                } \
                \
                /* move on */ \
                i = (i + 1) % (1 << bits); \
                assert((++o) != ((1 << bits) - 1)); \
            } \
            \
            return NULL; \
        } \
        \
        static inline void \
        ht_##name ## _for_each( \
            struct __ht_##name *ht, \
            ht_##name ## _func_type func, \
            void *arg \
        ) { \
            uint64_t t; \
            uint64_t i = find_first_bit(ht->bmap, 1 << bits); \
            /* break if there is no bit set in the map */ \
            if (unlikely(i == (1 << bits))) { \
                return; \
            } \
            \
            while (1) { \
                t = i; \
                func( \
                    atomic##klen ## _read(&(ht->cell[i].key)), \
                    &ht->cell[i].val, \
                    arg \
                ); \
                i = find_next_bit(ht->bmap, (1 << bits), i + 1); \
                \
                if (i == (1 << bits) || i <= t) { \
                    break; \
                } \
            } \
        } \


#define HOOK_CONFIG_HMAP_DEFINE(name, bits, klen) \
        /* typedef */ \
        typedef struct __ht_##name { \
            DECLARE_BITMAP(bmap, (1 << bits)); \
            struct  __htcell_##name { \
                uint##klen ## _t key; \
                struct name val; \
            } cell[1 << bits]; \
        } ht_##name ## _t; \
        \
        /* functions */ \
        static inline struct name * \
        ht_##name ## _get_slot( \
            struct __ht_##name *ht, \
            uint##klen ## _t k  \
        ) { \
            hash##bits ## _t i = hash_u##klen ## _into_h##bits(k); \
            hash##bits ## _t o = 0; \
            \
            while (test_and_set_bit(i, ht->bmap)) { \
                /* check existence */ \
                if (ht->cell[i].key == k) { \
                    return &(ht->cell[i].val); \
                } \
                \
                /* move on */ \
                i = (i + 1) % (1 << bits); \
                assert((++o) != ((1 << bits) - 1)); \
            } \
            \
            /* we are the first to set the bit */ \
            ht->cell[i].key = k; \
            return &(ht->cell[i].val); \
        } \
        \
        static inline struct name * \
        ht_##name ## _has_slot( \
            struct __ht_##name *ht, \
            uint##klen ## _t k  \
        ) { \
            hash##bits ## _t i = hash_u##klen ## _into_h##bits(k); \
            hash##bits ## _t o = 0; \
            \
            while (test_bit(i, ht->bmap)) { \
                /* check existence */ \
                if (ht->cell[i].key == k) { \
                    return &(ht->cell[i].val); \
                } \
                \
                /* move on */ \
                i = (i + 1) % (1 << bits); \
                assert((++o) != ((1 << bits) - 1)); \
            } \
            \
            return NULL; \
        } \

#endif // _PMRACE_INSTRUMENT_HOOK_HASH_H_