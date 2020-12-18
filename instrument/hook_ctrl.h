#ifndef _PMRACE_INSTRUMENT_HOOK_CTRL_H_
#define _PMRACE_INSTRUMENT_HOOK_CTRL_H_

#define _GNU_SOURCE

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sanitizer/dfsan_interface.h>

#include "hook_common.h"
#include "hook_hash.h"

#ifdef STACK_TRACE_ENABLE
#include "hook_trace.h"
#endif

extern atomic_int main_entered;
extern uint32_t g_instance_id;
// extern dfsan_label unflushed_label;

typedef enum persistency_state {
  PM_CLEAN = 0,
  PM_DIRTY,
  PM_UNDETERMINED
} pm_state_t;

/* memory cell */
struct hook_mc {
  pm_state_t stat;
  /* last access info */
  pid_32_t pid;
  hval_64_t inst;
};

/* shared info */
HOOK_HMAP_DEFINE(hook_mc, 24, 64)
// extern ht_hook_mc_t *g_hook_mc_reader_ht;
// extern ht_hook_mc_t *g_hook_mc_writer_ht;

#define _PATHNAME_MAX 1024

#define _COV_CFG_EDGE_BITS          (1 << 24)
#define _COV_DFG_EDGE_BITS          (1 << 24)
#define _COV_ALIAS_INST_BITS        (1 << 24)
#define _ANNOTATION_HINT_BITS       (1 << 24)

#define _PMRACE_INSTANCE_MAX 128

struct hook_shminfo {
  DECLARE_BITMAP(cov_cfg_edge, _COV_CFG_EDGE_BITS);
  DECLARE_BITMAP(cov_dfg_edge, _COV_DFG_EDGE_BITS);
  DECLARE_BITMAP(cov_alias_inst, _COV_ALIAS_INST_BITS);
  DECLARE_BITMAP(sync_inst, _ANNOTATION_HINT_BITS);
  DECLARE_BITMAP(sync_var_record, _ANNOTATION_HINT_BITS);
  atomic_int program_running[_PMRACE_INSTANCE_MAX];
};

/* shared info */
extern struct hook_shminfo *g_shminfo;

struct hook_im {
  uint32_t delay_us;
};

HOOK_CONFIG_HMAP_DEFINE(hook_im, 24, 64)

typedef enum mem_access_type {
  CANDIDATE_RACE_WRITE = 'c',
  MEM_READ = 'r',
  MEM_WRITE = 'w'
} mem_access_t;

struct hook_sync_point {
  hval_64_t hval;
  mem_access_t type;
  uint32_t skip;
  uint8_t is_enabled; // for reader
};

#define _SYNC_POINTS_MAX 1024

struct hook_sync_config {
  atomic32_t m;
  atomic32_t waiting_readers;
  atomic32_t has_privileged_reader;
  atomic32_t total_disabled;
  char padding[48];

  struct hook_sync_point pts[_SYNC_POINTS_MAX];
  uint32_t point_num;
  uint32_t thread_num;
  uint32_t allowed_reader;
};

#define PAIR_TYPE_PERSISTENCY_SET   (1 << 3)
#define PAIR_TYPE_FLUSHED_FLAG      (1 << 2)
#define PAIR_TYPE_PREV_WRITER       (1 << 1)
#define PAIR_TYPE_CURR_WRITER       (1)

// Note that we only care about the the persistency for data to be read.
// In other words, flushed flag only matters for "UWR_PAIR" and "PWR_PAIR"
typedef enum pair_type {
  // 0000(0) = 0(20)
  // this type is not race and used for access analysis only
  XRR_PAIR = 0,

  // 0001(1) = 1(10)
  XRW_PAIR = PAIR_TYPE_CURR_WRITER,

  // 1010(2) = 10(10)
  UWR_PAIR = (PAIR_TYPE_PERSISTENCY_SET | PAIR_TYPE_PREV_WRITER),

  // 0011(2) = 3(10)
  XWW_PAIR = (PAIR_TYPE_PREV_WRITER | PAIR_TYPE_CURR_WRITER),

  // 1110(2) = 14(10)
  PWR_PAIR = (UWR_PAIR | PAIR_TYPE_FLUSHED_FLAG)
} pair_type_t;

// extern const char *pm_state_str[];

extern const char *pair_type_str[];

struct pair_info {
  uint32_t hash;
  uint32_t pid1;
  uint32_t pid2;
  uint64_t from;
  uint64_t into;
  uint64_t addr;
  uint32_t size;
  uint32_t type;
};

#define _RACE_ENTRY_MAX           (14 * (1 << 20) / (4 * sizeof(uint64_t)))
#define _ANNOTATION_ENTRY_MAX     (1 << 20)

/* pair records used in data races and reading unflushed  */
struct hook_pair_records {
  atomic64_t count;                           /* number of entries in buffer */
  struct pair_info buffer[_RACE_ENTRY_MAX];
};

// struct hook_sync_var {
//   atomic64_t count;                           /* number of entries in buffer */
//   struct {
//     uint64_t addr;
//     uint64_t offset;
//     uint64_t size;
//     uint64_t val;                             /* assume size <= 8 bytes */
//   } buffer[_ANNOTATION_ENTRY_MAX];
// };

// We don't expect too much writes based on read unflushed
#define _DFSAN_RECORD_MAX 1024

struct hook_dfsan_records {
  atomic64_t count;
  struct {
    char hash_str[64];
    uint32_t id;
    pid_32_t pid;
    uint32_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    hval_64_t hval;
  } buffer[_DFSAN_RECORD_MAX];
};

/* log handler per-thread */
struct hook_log_handler {
  FILE *out;
  pid_32_t pid;
  // struct hook_stack_trace_node *next;
};

#define _LOG_HANDLER_MAX 24

struct hook_logs {
  atomic32_t count;
  struct hook_log_handler handlers[_LOG_HANDLER_MAX];
};

/* PM regions */
#define PM_POOL_CAND_MAX          128

extern const char *pm_pool_path_pattern;
extern uint32_t pm_pool_cand_fds[PM_POOL_CAND_MAX];

struct pm_regions_info {
  uint64_t count;
  struct {
    uint64_t begin;
    uint64_t end;
    uint32_t fd;
    uint32_t is_open;
  } regions[PM_POOL_CAND_MAX];
};

extern struct pm_regions_info pm_regions;

/* thread-local storage */
struct tx_range {
  uint64_t begin;
  uint64_t end;
  struct tx_range *next;
};

// record 3 pm writes per
#define UNFLUSHED_ENTRY_COUNT 3

struct unflushed_data {
  char hash_str[64];
  dfsan_label label;
  uint64_t addr;
  uint32_t count;
  struct unflushed_data *next;
};

struct tx_info {
  uint64_t pool_addr;
  uint32_t count; // number of nested tx
};

/* control block */
struct hook_cb {
  /* key */
  pid_32_t pid;

  /* for COV (cfg_edge) */
  hval_64_t last_blk;

  /* current transaction records */
  struct tx_range *tx_range_head;
  struct tx_info thread_tx_info;

  /* thread-local log handler */
  FILE *trace_stream;
  uint64_t thread_trace_count;

  /* thread-local records for reading unflushed */
  struct unflushed_data *unflushed_data_head;

  /* used for sync */
  uint32_t bypass_reader_sync;
  int32_t reader_id;

#ifdef STACK_TRACE_ENABLE
  /* used for backtracing */
  FILE *writer_backtrace;
  uint8_t *backtrace_buf;
  size_t backtrace_buf_size;
  hval_64_t last_sync_write_hval;
#endif
};

static inline void __hook_cb_free(uint32_t key, struct hook_cb* val, void *arg) {
  // no need to fclose(val->trace_stream) since we have already closing them in combine_all_traces
#ifdef STACK_TRACE_ENABLE
  if (val->backtrace_buf != NULL) {
    debug("freeing buf of size %lu starting at %p\n", val->backtrace_buf_size, val->backtrace_buf);
    fclose(val->writer_backtrace);
    free(val->backtrace_buf);
  }
#endif

  // TODO: free val->tx_range_head
  // TODO: free val->unflushed_data_head
}

typedef struct {
  pid_32_t pid;
  bool found_writer_cb;
  hval_64_t target_write_hval, read_hval;
  FILE *trace_stream;
} get_writer_stacktrace_arg;

#ifdef STACK_TRACE_ENABLE
static inline void __hook_cb_get_writer_stacktrace(uint32_t key,
                                                   struct hook_cb *val,
                                                   void *_arg) {
  get_writer_stacktrace_arg *arg = (get_writer_stacktrace_arg *)_arg;
  char c;

  if (arg->found_writer_cb == true) {
    return;
  }

  if (val->pid == arg->pid) {
    if (val->last_sync_write_hval != arg->target_write_hval) {
      debug("last sync write hval of thread tid-%u is %lu, while the UWR pair is %lu(W) %lu(R)\n",
          val->pid, val->last_sync_write_hval, arg->target_write_hval,
          arg->read_hval);
      return;
    }
    fprintf(arg->trace_stream, "corresponding writer: %lu\n",
            val->last_sync_write_hval);
    while ((c = fgetc(val->writer_backtrace)) != EOF) {
      fputc(c, arg->trace_stream);
    }
    fputc('\n', arg->trace_stream);
    fflush(arg->trace_stream);
    fseek(val->writer_backtrace, 0, SEEK_SET);

    // indicate that we have already found corresponding cb
    arg->found_writer_cb = true;
  }
}
#endif

HOOK_HMAP_DEFINE(hook_cb, 16, 32);
// extern ht_hook_cb_t *g_hook_cb_ht;

struct hook_sync_var {
  uint64_t addr;
  uint64_t offset;
  uint64_t size;
  uint64_t val;
};

HOOK_HMAP_DEFINE(hook_sync_var, 24, 64);

struct hook_cov_bitmaps {
  DECLARE_BITMAP(cov_cfg_edge, _COV_CFG_EDGE_BITS);
  DECLARE_BITMAP(cov_dfg_edge, _COV_DFG_EDGE_BITS);
  DECLARE_BITMAP(cov_alias_inst, _COV_ALIAS_INST_BITS);
};

/* runtime info */
struct hook_rtinfo {
  /* "public" coverage */
  atomic64_t cov_cfg_edge_incr;
  atomic64_t cov_dfg_edge_incr;
  atomic64_t cov_alias_inst_incr;
  atomic64_t sync_var_incr;

  /* "protected" coverage */
  atomic64_t cov_cfg_edge;
  atomic64_t cov_dfg_edge;
  atomic64_t cov_alias_inst;

  /* signals and flags */
  // A flag indicating the metadata construction and linkage.
  // atomic_int program_inited;
  atomic32_t is_trace_enabled;

  /* A flag to enable the backups for PM imgs */
  atomic32_t is_img_backup_enabled;

  /* input path */
  const char* img_path;

  /* output paths */
  const char* output_dir;
  const char* race_path;
  const char* unflushed_path;
  const char* cov_path;
  const char* skip_path;
  const char* dfsan_path;
  const char* stacktrace_path;

  /* instruction metadata (with delay) */
  ht_hook_im_t hook_delay_ht;
  struct hook_sync_config sync;

  /* Reader/Writer set of memory cells (at runtime) */
  ht_hook_mc_t hook_mc_reader_ht;
  ht_hook_mc_t hook_mc_writer_ht;

  /* Crontrol block info (at runtime) */
  ht_hook_cb_t hook_cb_ht;

  /* hashmap for synchronization variables */
  ht_hook_sync_var_t hook_sync_var_ht;

  /* storage of new memdu and race instances */
  struct hook_pair_records new_memdu;
  struct hook_pair_records new_races;

  /* storage of current memdu and race instances */
  struct hook_pair_records curr_memdu;
  struct hook_pair_records curr_races;

  /* storeage of dfsan records for  */
  struct hook_dfsan_records dfsan_records;

  struct hook_logs logs;

  /* cov info shared by parent and children processes */
  int cov_shmid;
  struct hook_cov_bitmaps bitmaps;
};

/* private info */
extern struct hook_rtinfo *g_rtinfo;
// extern struct hook_pair_records *g_new_races;
// extern struct hook_pair_records *g_new_memdu;
// extern _Atomic(struct hook_stack_trace_node *) g_stack_traces;


static inline uint8_t is_added_in_tx(struct hook_cb *cb, uint64_t addr) {
  struct tx_range *it = cb->tx_range_head;

  while (it != NULL) {
    if (addr >= it->begin && addr <= it->end) {
      return 1;
    }

    it = it->next;
  }

  return 0;
}

/* operations */
static inline void cov_cfg_add_edge(hash24_t edge) {
  if (!test_and_set_bit(edge, g_shminfo->cov_cfg_edge)) {
    atomic_fetch_add(&g_rtinfo->cov_cfg_edge_incr, 1);
  }
}

static inline void cov_dfg_add_edge(struct hook_cb *cb, hash24_t edge,
                                    hval_64_t from, hval_64_t into,
                                    uint64_t addr, uint64_t size,
                                    pair_type_t type) {

  /* record current memdus (new for this execution) */
  if (!test_and_set_bit(edge, g_rtinfo->bitmaps.cov_dfg_edge)) {
    atomic_fetch_add(&g_rtinfo->cov_dfg_edge, 1);

    // only interested in memdu for read unflushed
    if (type != UWR_PAIR && g_rtinfo->is_trace_enabled == 0) {
      return;
    }

    uint64_t offset;
    /* calculate the offset */
    offset = atomic_fetch_add(&g_rtinfo->curr_memdu.count, 1);
    if (offset >= _RACE_ENTRY_MAX) {
        return;
    }

    debug("current memdus: %lu [memdu-%u] [tid-%u] [pid-%u]\n",
      offset + 1, edge, cb->pid, getpid());

    /* do the recording */
    g_rtinfo->curr_memdu.buffer[offset].pid1 = cb->pid;
    g_rtinfo->curr_memdu.buffer[offset].pid2 = cb->pid;
    g_rtinfo->curr_memdu.buffer[offset].hash = edge;
    g_rtinfo->curr_memdu.buffer[offset].from = from;
    g_rtinfo->curr_memdu.buffer[offset].into = into;
    g_rtinfo->curr_memdu.buffer[offset].addr = addr;
    g_rtinfo->curr_memdu.buffer[offset].size = size;
    g_rtinfo->curr_memdu.buffer[offset].type = type;
  }

  /* record new memdus (new for this fuzzing) */
  if (!test_and_set_bit(edge, g_shminfo->cov_dfg_edge)) {
    atomic_fetch_add(&g_rtinfo->cov_dfg_edge_incr, 1);

    // only interested in memdu for read unflushed
    if (type != UWR_PAIR && g_rtinfo->is_trace_enabled == 0) {
      return;
    }

    uint64_t offset;
    /* calculate the offset */
    offset = atomic_fetch_add(&g_rtinfo->new_memdu.count, 1);
    if (offset >= _RACE_ENTRY_MAX) {
        return;
    }

    debug("new memdus: %lu [memdu-%u] [tid-%u] [pid-%u]\n",
      offset + 1, edge, cb->pid, getpid());

    if (type == UWR_PAIR) {
      char label_buf[64];
      sprintf(label_buf, "memdu-%u", edge);

      struct unflushed_data *temp = malloc(sizeof *temp);
      strcpy(temp->hash_str, label_buf);
      temp->addr = addr;
      temp->count = UNFLUSHED_ENTRY_COUNT;
      temp->label = dfsan_create_label(label_buf, NULL);
      dfsan_set_label(temp->label, (void*)addr, (size_t)size);
      temp->next = cb->unflushed_data_head;
      cb->unflushed_data_head = temp;
      // unflushed_label = dfsan_create_label(label_buf, NULL);
      // dfsan_set_label(unflushed_label, (void*)addr, (size_t)size);
      debug("create label (memdu) for 0x%016lx(addr), %lu(size), %s\n", addr, size, label_buf);

      fprintf(cb->trace_stream,
              "[PM sequential inconsistency bug] "
              "read unflushed: 0x%016lx(addr) %lu(size) %lu(W) %lu(R)\n",
              addr, size, from, into);

#ifdef STACK_TRACE_ENABLE
      fprintf(cb->trace_stream, "hash: memdu-%u\n", edge);
      fprintf(cb->trace_stream, "memdu: %lu(R) 0x%016lx(addr)\n", into, addr);
      printStackTrace(cb->trace_stream, 2);

      if (g_rtinfo->sync.point_num != 0) {
        get_writer_stacktrace_arg arg;
        arg.found_writer_cb = false;
        arg.pid = cb->pid;
        arg.target_write_hval = from;
        arg.read_hval = into;
        arg.trace_stream = cb->trace_stream;

        fprintf(cb->trace_stream, "hash: memdu-%u-writer\n", edge);
        debug("hash: memdu-%u-writer\n", edge);
        ht_hook_cb_for_each(&g_rtinfo->hook_cb_ht,
                            __hook_cb_get_writer_stacktrace, &arg);

        if (arg.found_writer_cb == false) {
          debug("No corresponding writer in UWR pair %lu(W) %lu(R)\n", from, into);
        }
      }
#endif
    }

    /* do the recording */
    g_rtinfo->new_memdu.buffer[offset].pid1 = cb->pid;
    g_rtinfo->new_memdu.buffer[offset].pid2 = cb->pid;
    g_rtinfo->new_memdu.buffer[offset].hash = edge;
    g_rtinfo->new_memdu.buffer[offset].from = from;
    g_rtinfo->new_memdu.buffer[offset].into = into;
    g_rtinfo->new_memdu.buffer[offset].addr = addr;
    g_rtinfo->new_memdu.buffer[offset].size = size;
    g_rtinfo->new_memdu.buffer[offset].type = type;
  }
}

static inline void cov_alias_add_pair(struct hook_cb *cb, hash24_t pair,
                                      pid_32_t prev_pid,
                                      hval_64_t from, hval_64_t into,
                                      uint64_t addr, uint64_t size,
                                      pair_type_t type) {

  /* record current races (new for this execution) */
  if (!test_and_set_bit(pair, g_rtinfo->bitmaps.cov_alias_inst)) {
    atomic_fetch_add(&g_rtinfo->cov_alias_inst, 1);

    uint64_t offset;
    /* calculate the offset */
    offset = atomic_fetch_add(&g_rtinfo->curr_races.count, 1);
    if (offset >= _RACE_ENTRY_MAX) {
        return;
    }

    debug("current races: %lu [alias-%u] [tid-%u] [pid-%u]\n",
      offset + 1, pair, cb->pid, getpid());

    /* do the recording */
    g_rtinfo->curr_races.buffer[offset].pid1 = prev_pid;
    g_rtinfo->curr_races.buffer[offset].pid2 = cb->pid;
    g_rtinfo->curr_races.buffer[offset].hash = pair;
    g_rtinfo->curr_races.buffer[offset].from = from;
    g_rtinfo->curr_races.buffer[offset].into = into;
    g_rtinfo->curr_races.buffer[offset].addr = addr;
    g_rtinfo->curr_races.buffer[offset].size = size;
    g_rtinfo->curr_races.buffer[offset].type = type;
  }

  /* record new races (new for this fuzzing) */
  if (!test_and_set_bit(pair, g_shminfo->cov_alias_inst)) {
    atomic_fetch_add(&g_rtinfo->cov_alias_inst_incr, 1);

    uint64_t offset;
    /* calculate the offset */
    offset = atomic_fetch_add(&g_rtinfo->new_races.count, 1);
    if (offset >= _RACE_ENTRY_MAX) {
        return;
    }

    debug("new races: %lu [alias-%u] [tid-%u] [pid-%u]\n",
      offset + 1, pair, cb->pid, getpid());

    if (type == UWR_PAIR) {
      char label_buf[64];
      sprintf(label_buf, "alias-%u", pair);

      struct unflushed_data *temp = malloc(sizeof *temp);
      strcpy(temp->hash_str, label_buf);
      temp->addr = addr;
      temp->count = UNFLUSHED_ENTRY_COUNT;
      temp->label = dfsan_create_label(label_buf, NULL);
      dfsan_set_label(temp->label, (void*)addr, (size_t)size);
      temp->next = cb->unflushed_data_head;
      cb->unflushed_data_head = temp;
      // unflushed_label = dfsan_create_label(label_buf, NULL);
      // dfsan_set_label(unflushed_label, (void*)addr, (size_t)size);
      debug("create label (alias) for 0x%016lx(addr), %lu(size), %s\n", addr, size, label_buf);

      fprintf(cb->trace_stream, "[PM inter-thread inconsistency bug] read unflushed: ");
      fprintf(cb->trace_stream, "0x%016lx(addr) %lu(size) %lu(W) %lu(R)\n",
        addr, size, from, into);

#ifdef STACK_TRACE_ENABLE
      fprintf(cb->trace_stream, "hash: alias-%u\n", pair);
      fprintf(cb->trace_stream, "alias: %lu(R) 0x%016lx(addr)\n", into, addr);
      printStackTrace(cb->trace_stream, 2);

      if (g_rtinfo->sync.point_num != 0) {
        get_writer_stacktrace_arg arg;
        arg.found_writer_cb = false;
        arg.pid = prev_pid;
        arg.target_write_hval = from;
        arg.read_hval = into;
        arg.trace_stream = cb->trace_stream;

        fprintf(cb->trace_stream, "hash: alias-%u-writer\n", pair);
        debug("hash: alias-%u-writer\n", pair);
        ht_hook_cb_for_each(&g_rtinfo->hook_cb_ht,
                            __hook_cb_get_writer_stacktrace, &arg);

        if (arg.found_writer_cb == false) {
          debug("No corresponding writer in UWR pair %lu(W) %lu(R)\n", from, into);
        }
      }
#endif
    } else {
      fprintf(cb->trace_stream, "data races: [%s] ", pair_type_str[type]);
      fprintf(cb->trace_stream, "0x%016lx(addr) %lu(size) %lu(W) %lu(R)\n",
        addr, size, from, into);
    }

    /* do the recording */
    g_rtinfo->new_races.buffer[offset].pid1 = prev_pid;
    g_rtinfo->new_races.buffer[offset].pid2 = cb->pid;
    g_rtinfo->new_races.buffer[offset].hash = pair;
    g_rtinfo->new_races.buffer[offset].from = from;
    g_rtinfo->new_races.buffer[offset].into = into;
    g_rtinfo->new_races.buffer[offset].addr = addr;
    g_rtinfo->new_races.buffer[offset].size = size;
    g_rtinfo->new_races.buffer[offset].type = type;


  }
  else if (type == UWR_PAIR) {
    debug("Redundant UWR alias pair: 0x%016lx(addr) %lu(size) %lu(W) %lu(R)\n",
      addr, size, from, into);
  }
}

static inline void __hook_sync_var_set_cell(hval_64_t key, struct hook_sync_var *val, void *arg) {
  struct hook_sync_var *r = (struct hook_sync_var *)arg;
  val->addr = r->addr;
  val->offset = r->offset;
  val->size = r->size;
  val->val = r->val;
}

static inline void annotation_add_sync_hint(hval_64_t key, uint64_t addr, uint64_t addr_offset,
                                            uint64_t size, uint64_t val) {
  if (ht_hook_sync_var_has_slot(&g_rtinfo->hook_sync_var_ht, key, NULL, NULL))
    return;

  /* record new synchronizatino variables */
  struct hook_sync_var sv = {.addr = addr, .offset = addr_offset, .size = size, .val = val};
  ht_hook_sync_var_get_slot(&g_rtinfo->hook_sync_var_ht, key, __hook_sync_var_set_cell, &sv);

  debug("new sync var hint: key = %lu, addr = 0x%lx\n", key, addr);

  // /* record new synchronizatino variables */
  // if (!test_and_set_bit(key, g_shminfo->annotation_hint)) {
  //   // atomic_fetch_add(&g_rtinfo->sync_var_incr, 1);

  //   uint64_t offset = atomic_fetch_add(&g_rtinfo->sync_hints.count, 1);
  //   if (offset >= _ANNOTATION_ENTRY_MAX) {
  //     debug("overflow sync_hint's buffer\n");
  //     return;
  //   }

  //   debug("new sync var hint: %lu, key = %u, addr = 0x%lx\n",
  //     offset, key, addr);

  //   /* record the new hint for synchronization */
  //   g_rtinfo->sync_hints.buffer[offset].addr = addr;
  //   g_rtinfo->sync_hints.buffer[offset].offset = addr_offset;
  //   g_rtinfo->sync_hints.buffer[offset].size = size;
  //   g_rtinfo->sync_hints.buffer[offset].val = val;
  // }
}

#define FTOK_KEY "/dev/null"


static inline int attach_shared_coverage_info() {
  key_t key;
  if ((key= ftok(FTOK_KEY, 2333)) == -1) {
    perror("ftok");
    return -1;
  }

  int shmid = shmget(key, sizeof(struct hook_shminfo), 0666|IPC_CREAT);
  if (shmid == -1) {
    perror("Shared memory shmget");
    return -1;
  }

  g_shminfo = shmat(shmid, NULL, 0);
  if (g_shminfo == (void *) -1) {
    perror("Shared memory attach");
    return -1;
  }

  return shmid;
}

static inline int attach_runtime_info() {
  int cov_shmid = shmget(
    IPC_PRIVATE, sizeof(struct hook_rtinfo), 0666|IPC_CREAT
  );
  if (cov_shmid == -1) {
    perror("Shared memory shmget 2");
    return -1;
  }

  g_rtinfo = shmat(cov_shmid, NULL, 0);
  if (g_rtinfo == (void *) -1) {
    perror("Shared memory attach 2");
    return -1;
  }
  g_rtinfo->cov_shmid = cov_shmid;

  return cov_shmid;
}

static inline int detach_shared_coverage_info() {
  // assert(g_shminfo);

  // if (shmdt(g_shminfo) == -1) {
  //   perror("shmdt");
  //   return -1;
  // }

  int shmid = g_rtinfo->cov_shmid;
  if (shmdt(g_rtinfo) == -1) {
    perror("shmdt 2");
    return -1;
  }

  shmctl(shmid, IPC_RMID, 0);

  return 0;
}

int init_shared_coverage_info();

int free_shared_coverage_info();

void dump_new_races();

/* control block api */
static inline void hook_cb_init(struct hook_cb *cb, pid_32_t pid) {
  cb->pid = pid;
#ifdef STACK_TRACE_ENABLE
  cb->writer_backtrace = open_memstream((char **)&cb->backtrace_buf, &cb->backtrace_buf_size);
  cb->last_sync_write_hval = 0;
#endif

  /* no basic block visited on start */
  assert(cb->last_blk == 0);

  // char path_buf[64];
  // sprintf(path_buf, "/tmp/pmrace-pid-%u", pid);
  // cb->trace_stream = fopen(path_buf, "w+");

  // cb->trace_stream = tmpfile();
  // assert(cb->trace_stream != NULL);

  // the default value shoule be 0 (due to 'memset')
  assert(cb->bypass_reader_sync == 0);
  assert(cb->reader_id == 0);
  assert(cb->unflushed_data_head == 0);
}

static inline struct hook_cb *hook_cb_create(pid_32_t pid) {
  struct hook_cb *cb;

  /*
   * Since the key is thread_id, the access to g_hook_cb_ht
   * is sequential. No need for atomic access via callback func.
   */
  // cb = ht_hook_cb_get_slot(g_hook_cb_ht, pid, NULL, NULL);
  cb = ht_hook_cb_get_slot(&g_rtinfo->hook_cb_ht, pid, NULL, NULL);
  assert(cb != NULL);

  /* initialize cb */
  hook_cb_init(cb, pid);

  return cb;
}

static inline struct hook_cb *hook_cb_find(pid_32_t pid) {
  /*
   * Since the key is thread_id, the access to g_hook_cb_ht
   * is sequential. No need for atomic access via callback func.
   */
    // return ht_hook_cb_has_slot(g_hook_cb_ht, pid, NULL, NULL);
    return ht_hook_cb_has_slot(&g_rtinfo->hook_cb_ht, pid, NULL, NULL);
}

static inline struct hook_cb *hook_cb_get_or_create(pid_32_t pid) {
  struct hook_cb *cb = hook_cb_find(pid);

  if (unlikely(cb == NULL)) {
    cb = hook_cb_create(pid);
    debug("hook_cb_create should occur only few (#threads) times [pid:%u]\n", pid);

    char cmd[256];
    // FIXME: options for path
    sprintf(cmd, "cp /proc/%d/maps %s/maps/maps_%d",
      pid, g_rtinfo->output_dir, pid);
    debug("cmd: %s\n", cmd);
    system(cmd);

    // allocate a log handler entry
    uint32_t hd_idx = atomic_fetch_add(&g_rtinfo->logs.count, 1);
    assert(hd_idx < _LOG_HANDLER_MAX);
    // create tmpfs for stacktrace output
    // struct hook_stack_trace_node *temp = malloc(
    //   sizeof(struct hook_stack_trace_node));
    // if (unlikely(temp == NULL)) {
    //   perror("bad alloc!");
    //   exit(1);
    // }

    cb->trace_stream = g_rtinfo->logs.handlers[hd_idx].out;
    debug(
        "create trace_stream %p thread_trace_count %lu tx_range_head %p "
        "[pid:%u]\n",
        cb->trace_stream, cb->thread_trace_count, cb->tx_range_head, pid);

    assert(cb->thread_trace_count == 0);

    g_rtinfo->logs.handlers[hd_idx].pid = pid;
    // temp->pid = pid;
    // temp->out = cb->trace_stream;

    // struct hook_stack_trace_node *expected;;
    // do {
    //   expected = atomic_load(&g_stack_traces);
    //   temp->next = expected;
    // } while (!atomic_compare_exchange_weak(&g_stack_traces, &expected, temp));

    // debug("observe %lu pm regions [pid:%u]\n", pm_regions.count, pid);
    // if (pm_regions.count == 1) {
    //   debug("region info [0x%lx, 0x%lx]\n",
    //     pm_regions.regions[0].begin, pm_regions.regions[0].end);
    // }
  }

  return cb;
}

static inline void combine_all_traces(FILE *out) {
  // struct hook_stack_trace_node *cur = atomic_load(&g_stack_traces);
  // while (cur != NULL) {
  //   debug("processing trace %p [pid-%u]\n", cur->out, cur->pid);
  //   rewind(cur->out);

  //   char c;
  //   while ((c = fgetc(cur->out)) != EOF)
  //     fputc(c, out);
  //   fputc('\n', out);
  //   debug("done trace %p [pid-%u]\n", cur->out, cur->pid);

  //   cur = cur->next;
  // }

  uint32_t i;
  struct hook_log_handler *cur;
  for (i = 0; i < g_rtinfo->logs.count; i++) {
    cur = &g_rtinfo->logs.handlers[i];
    debug("processing trace %p [pid-%u]\n", cur->out, cur->pid);
    rewind(cur->out);

    char c;
    while ((c = fgetc(cur->out)) != EOF)
      fputc(c, out);
    fputc('\n', out);
    fflush(out);
    fclose(cur->out);
    debug("done trace %u-th %p [pid-%u]\n", i, cur->out, cur->pid);
  }
}

// static inline int find_stack_trace(pid_32_t pid, uint32_t hash) {
//   // find thread-local stack trace stream
//   struct hook_stack_trace_node *cur = atomic_load(&g_stack_traces);
//   while (cur != NULL && cur->pid != pid) {
//     cur = cur->next;
//   }
//   assert(cur != NULL);

//   char *line = NULL;
//   size_t len = 0;
//   ssize_t nread;
//   int found = 0;
//   while (1) {
//     nread = getline(&line, &len, cur->out);
//     if (nread == -1)
//       break;

//     // wait for starting token, i.e., "hash: "
//     if (strncmp(line, "hash: ", 6) != 0)
//       continue;

//     char *ptr;
//     uint32_t v = strtoul(line + 6, &ptr, 10);
//     assert(v == hash);
//     found = 1;
//   }


// }

// return value
//       0: region in DRAM
//       1: region in PM
//      -1: region consists fo DRAM and PM
static inline int32_t is_region_in_pmem(uint64_t addr, uint64_t size) {
  if (pm_regions.count == 0) {
    return 0;
  }

  uint64_t i;
  for (i = 0; i < pm_regions.count; i++) {
    if (pm_regions.regions[i].is_open) {
      if (addr >= pm_regions.regions[i].begin
        && (addr + size) <= pm_regions.regions[i].end) {
        return 1;
      }
      else if (addr <= pm_regions.regions[i].end
        && (addr + size) >= pm_regions.regions[i].begin) {
          return -1;
        }
    }
  }

  return 0;
}

// make a snapshot of current pm img
#define DO_BACKUP_IMG(tag, id) \
  char backup_img_dir[512]; \
  /* skip the suffix of "---cov" */ \
  snprintf(backup_img_dir, strlen(g_rtinfo->cov_path) - 5, "%s", g_rtinfo->cov_path); \
  if (g_rtinfo->is_img_backup_enabled) { \
    char cmd[1024]; \
    sprintf(cmd, "cp %s %s/pmem-%s-%lu.img", g_rtinfo->img_path, backup_img_dir, tag, id); \
    debug("cmd: %s\n", cmd); \
    system(cmd); \
  } \


#define FILTER_NON_PM_ACCESS(addr, size) \
    switch (is_region_in_pmem(addr, size)) { \
      case -1: \
        fprintf(stderr, "%s [0x%lx, 0x%lx], size: %lu, consists of DRAM and PM\n", \
          __func__, addr, size, addr + size); \
        return; \
      case 0: \
        /* we do not care DRAM access */ \
        /* debug("[0x%lx, 0x%lx] DRAM only\n", addr, addr + size); */ \
        return; \
      case 1: \
        /* PM access */ \
        break; \
      default: \
        fprintf(stderr, "unknown results\n"); \
        return; \
    } \

#define HOOK_HANDLER_BEGIN() \
  if ((atomic_load(&main_entered) == 0) || \
    (atomic_load(&g_shminfo->program_running[g_instance_id]) == 0)) \
    return; \

#endif // _PMRACE_INSTRUMENT_HOOK_CTRL_H_
