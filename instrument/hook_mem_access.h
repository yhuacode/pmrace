#ifndef _PMRACE_INSTRUMENT_HOOK_MEM_ACCESS_H_
#define _PMRACE_INSTRUMENT_HOOK_MEM_ACCESS_H_

#include "hook_common.h"
#include "hook_ctrl.h"

static inline void __hook_mc_read_cell(
    hval_64_t key, struct hook_mc *val, void *arg
) {
    struct hook_mc *r = (struct hook_mc *) arg;
    r->stat = val->stat;
    r->pid = val->pid;
    r->inst = val->inst;
}

static inline void __hook_mc_set_cell(
    hval_64_t key, struct hook_mc *val, void *arg
) {
    struct hook_mc *r = (struct hook_mc *) arg;
    val->stat = r->stat;
    val->pid = r->pid;
    val->inst = r->inst;
}

static inline void __hook_mc_set_cell_state(
    hval_64_t key, struct hook_mc *val, void *arg
) {
    struct hook_mc *r = (struct hook_mc *) arg;
    val->stat = r->stat;
}

static inline void __hook_mc_read_and_set_cell(
    hval_64_t key, struct hook_mc *val, void *arg
) {
    struct hook_mc tmp;
    tmp.stat = val->stat;
    tmp.pid = val->pid;
    tmp.inst = val->inst;

    struct hook_mc *r = (struct hook_mc *) arg;
    val->stat = r->stat;
    val->pid = r->pid;
    val->inst = r->inst;

    r->stat = tmp.stat;
    r->pid = tmp.pid;
    r->inst = tmp.inst;
}

// static inline void __mem_check_alias ()

// static inline void mem_check_alias_writer_for_reader(
//         pid_32_t ptid, hval_64_t inst, uint64_t addr,
//         hval_64_t *s, hval_64_t *p,
//         ht_hook_mc_func_type func, void *arg
// ) {
//     struct hook_mc cell;
//     if (arg) {
//         cell.pid = ((struct hook_mc *)(arg))->pid;
//         cell.inst = ((struct hook_mc *)(arg))->inst;
//     }

//     void *r = ht_hook_mc_has_slot(
//         g_hook_mc_## rw ## _ht,
//         addr,
//         func,
//         &cell);
//     if (!r) {
//         /* exit if no counterpart cell exists */
//         *s = 0;
//         *p = 0;
//     }

//     else if (cell.pid == ptid) {
//         /* found an memdu pair, report it */
//         *s = cell.inst;
//         *p = 0;
//     }

//     else {
//         /* found an alias pair, report it */
//         *s = 0;
//         *p = cell.inst;
//     }
// }

static inline void mem_check_alias_writer_for_reader(
        pid_32_t ptid, hval_64_t inst, uint64_t addr,
        hval_64_t *s, hval_64_t *p,
        pair_type_t *mt, pair_type_t *rt,
        struct hook_mc *cell, pid_32_t *prev_ptid, uint8_t in_tx
) {
    void *r = ht_hook_mc_has_slot(
        // g_hook_mc_writer_ht,
        &g_rtinfo->hook_mc_writer_ht,
        addr,
        __hook_mc_read_cell,
        cell);
    if (!r) {
        /* exit if no counterpart cell exists */
        *s = 0;
        *p = 0;
    }

    else if (cell->pid == ptid) {
        /* found an memdu pair, report it */
        *s = cell->inst;
        *p = 0;
        *prev_ptid = cell->pid;
        if (cell->stat == PM_DIRTY && !in_tx) {
            *mt = UWR_PAIR;
        }
        else {
            *mt = PWR_PAIR;
        }
    }

    else {
        /* found an alias pair, report it */
        *s = 0;
        *p = cell->inst;
        *prev_ptid = cell->pid;
        if (cell->stat == PM_DIRTY && !in_tx) {
            *rt = UWR_PAIR;
        }
        else {
            *rt = PWR_PAIR;
        }
    }
}

static inline void mem_check_alias_reader(
        pid_32_t ptid, hval_64_t inst, uint64_t addr,
        hval_64_t *s, hval_64_t *p, pid_32_t *prev_ptid
) {
    struct hook_mc cell;

    void *r = ht_hook_mc_has_slot(
        // g_hook_mc_reader_ht,
        &g_rtinfo->hook_mc_reader_ht,
        addr,
        __hook_mc_read_cell,
        &cell);
    if (!r) {
        /* exit if no counterpart cell exists */
        *s = 0;
        *p = 0;
    }

    else if (cell.pid == ptid) {
        /* found an memdu pair, report it */
        *s = cell.inst;
        *p = 0;
        *prev_ptid = cell.pid;
    }

    else {
        /* found an alias pair, report it */
        *s = 0;
        *p = cell.inst;
        *prev_ptid = cell.pid;
    }
}

static inline void mem_check_alias_writer_for_writer(
        pid_32_t ptid, hval_64_t inst, uint64_t addr,
        hval_64_t *s, hval_64_t *p, struct hook_mc *cell,
        pid_32_t *prev_ptid
) {
    void *r = ht_hook_mc_get_slot(
        // g_hook_mc_writer_ht,
        &g_rtinfo->hook_mc_writer_ht,
        addr,
        __hook_mc_read_and_set_cell,
        cell);
    if (cell->pid == 0 && cell->inst == 0) {
        /* exit if no counterpart cell exists */
        *s = 0;
        *p = 0;
    }

    else if (cell->pid == ptid) {
        /* found an memdu pair, report it */
        *s = cell->inst;
        *p = 0;
        *prev_ptid = cell->pid;
    }

    else {
        /* found an alias pair, report it */
        *s = 0;
        *p = cell->inst;
        *prev_ptid = cell->pid;
    }
}

// /* generics */
// #define mem_check_alias(rw) \
//         static inline void mem_check_alias_##rw( \
//                 pid_32_t ptid, hval_64_t inst, uint64_t addr, \
//                 hval_64_t *s, hval_64_t *p, \
//                 ht_hook_mc_func_type func, void *arg\
//         ) { \
//             struct hook_mc cell; \
//             if (arg) { \
//                 cell.pid = ((struct hook_mc *)(arg))->pid; \
//                 cell.inst = ((struct hook_mc *)(arg))->inst; \
//             } \
//             \
//             void *r = ht_hook_mc_has_slot( \
//                 g_hook_mc_## rw ## _ht, \
//                 addr, \
//                 func, \
//                 &cell); \
//             if (!r) { \
//                 /* exit if no counterpart cell exists */ \
//                 *s = 0; \
//                 *p = 0; \
//             } \
//             \
//             else if (cell.pid == ptid) { \
//                 /* found an memdu pair, report it */ \
//                 *s = cell.inst; \
//                 *p = 0; \
//             } \
//             \
//             else { \
//                 /* found an alias pair, report it */ \
//                 *s = 0; \
//                 *p = cell.inst; \
//             } \
//         }

// mem_check_alias(reader)

// mem_check_alias(writer)

static inline void check_read_unflushed(struct hook_mc *cell) {

}

#define ALIAS_CHECK_DECLARE(icur, pcur) \
        uint64_t icur; \
        hval_64_t pcur; \


#define ALIAS_CHECK_INIT(icur, pcur) \
        icur = 0; \
        pcur = 0; \

#define ALIAS_CHECK_LOOP(cb, hval, pid, addr, i, p, icur, pcur, ppid, type) \
        if (pcur != p) { \
            if (pcur) { \
                cov_alias_add_pair( \
                    cb, hash_triple_u64_into_h24(pcur, hval, type), ppid, \
                    pcur, hval, addr + icur, i - icur + 1, type); \
            } \
            ppid = pid; \
            pcur = p; \
            icur = i; \
        } \

#define ALIAS_CHECK_FINI(cb, hval, addr, size, icur, pcur, ppid, type) \
        if (pcur) { \
            cov_alias_add_pair( \
                cb, hash_triple_u64_into_h24(pcur, hval, type), ppid, \
                pcur, hval, addr + icur, size - icur, type); \
        } \

#define MEMDU_CHECK_DECLARE(icur, scur) \
        uint64_t icur; \
        hval_64_t scur; \

#define MEMDU_CHECK_INIT(icur, scur) \
        icur = 0; \
        scur = 0; \

#define MEMDU_CHECK_LOOP(cb, hval, addr, i, s, icur, scur, type) \
        if (scur != s) { \
            if (scur) { \
                cov_dfg_add_edge( \
                    cb, hash_triple_u64_into_h24(scur, hval, type), \
                    scur, hval, addr + icur, i - icur + 1, type); \
            } \
            scur = s; \
            icur = i; \
        } \

#define MEMDU_CHECK_FINI(cb, hval, addr, size, icur, scur, type) \
        if (scur) { \
            cov_dfg_add_edge( \
                cb, hash_triple_u64_into_h24(scur, hval, type), \
                scur, hval, addr + icur, size - icur, type); \
        } \

#endif // _PMRACE_INSTRUMENT_HOOK_MEM_ACCESS_H_