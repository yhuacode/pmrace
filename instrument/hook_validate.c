#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <error.h>
#include <sys/types.h>

#include "hook_common.h"
#include "hook_ctrl.h"
#include "hook_mem_access.h"

static char* output_dir;

static char* inconsistent_write_path;
static char* sync_var_path;

static char* stacktrace_path;
static FILE* f_stack;

static char* status_path;

#define INCONSISTENT_WRITE_RECORD_MAX 1024

struct validate_runtime_info {
  int shmid;
  ht_hook_mc_t hook_mc_ht;
  pthread_mutex_t f_stack_mutex;
  struct {
    uint8_t transformed;
    _Atomic uint64_t count;
    struct {
      _Atomic uint8_t enabled;
      uint64_t offset;
      uint64_t size;
      uint64_t begin;
      uint64_t end;

      // initialized value for sync var
      uint64_t init_sync_value;
    } buffer[INCONSISTENT_WRITE_RECORD_MAX];
  } inconsistent_info;
};

static struct validate_runtime_info* g_validate;

void hook_main_exit();

// used in validation only
static inline void report_finding_in_validation(
  uint32_t id, hval_64_t hval, uint64_t addr, uint64_t size, const char* tag
) {
#ifdef STACK_TRACE_ENABLE
    pid_t tid = get_thread_id();
    struct hook_cb *cb = hook_cb_find(tid);
    if (unlikely(cb == NULL)) {
      hook_cb_create(tid);
      char cmd[256];
      // FIXME: options for path
      sprintf(cmd, "cp /proc/%d/maps %s/maps/maps_%d",
        tid, output_dir, tid);
      debug("cmd: %s\n", cmd);
      system(cmd);
    }

    pthread_mutex_lock(&g_validate->f_stack_mutex);
    fprintf(f_stack, "hash: %s-%u-%u\n", tag, tid, id);
    fprintf(f_stack, "%s: %lu(hval) 0x%016lx(addr) %lu(size)\n", tag, hval, addr, size);
    printStackTrace(f_stack, 0);
    pthread_mutex_unlock(&g_validate->f_stack_mutex);
#else
    debug("Found %s: %u(id) %lu(hval) 0x%016lx(addr)\n",
      tag, id, hval, addr);
#endif
    // thanks to the finds, we can stop the execution here
    hook_main_exit();
    exit(0);
}

static inline void set_inconsistent_memory(size_t pool_idx) {
  // abuse the PM_DIRTY to indicate inconsistent data
  static struct hook_mc cell = {.stat = PM_DIRTY, .pid = 0, .inst = 0};

  uint64_t addr, size;
  uint64_t i, j;
  for (i = 0; i < g_validate->inconsistent_info.count; i++) {
    addr = g_validate->inconsistent_info.buffer[i].offset + pm_regions.regions[pool_idx].begin;
    size = g_validate->inconsistent_info.buffer[i].size;

    g_validate->inconsistent_info.buffer[i].begin = addr;
    g_validate->inconsistent_info.buffer[i].end =
      addr + g_validate->inconsistent_info.buffer[i].size;

    for (j = 0; j < size; j++) {
      ht_hook_mc_get_slot(&g_validate->hook_mc_ht, addr + j, __hook_mc_set_cell, &cell);
    }
  }

  g_validate->inconsistent_info.transformed = 1;



}

void hook_main_enter() {
  debug("main begin\n");

  /* init shared memory */
  // Link coverage data in shared memory
  int shmid = attach_shared_coverage_info();
  if (shmid == -1) {
    perror("hook_main_enter attach");
    exit(1);
  }
  fprintf(stdout, "shmid: %d\n", shmid);

  shmid = shmget(
    IPC_PRIVATE, sizeof(struct validate_runtime_info), 0666|IPC_CREAT
  );
  if (shmid == -1) {
    perror("Shared memory shmget 2");
    exit(1);
  }

  g_validate = shmat(shmid, NULL, 0);
  if (g_validate == (void *) -1) {
    perror("Shared memory attach 2");
    exit(1);
  }
  g_validate->shmid = shmid;

  memset(&g_validate->hook_mc_ht, 0, sizeof(ht_hook_mc_t));

  /* set up global variables (including I/O paths) */
  if ((output_dir = getenv("OUTPUT_DIR")) == NULL) {
    fprintf(stderr, "OUTPUT_DIR not found\n");
    exit(1);
  }
  debug("OUTPUT_DIR found: %s\n", output_dir);

  if ((sync_var_path = getenv("PMRACE_SYNC_VAR_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_SYNC_VAR_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_SYNC_VAR_PATH  found: %s\n", sync_var_path);

  if ((inconsistent_write_path = getenv("PMRACE_INCONSISTENT_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_INCONSISTENT_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_INCONSISTENT_PATH found: %s\n", inconsistent_write_path);

  if (strcmp(sync_var_path, "") == 0) {
    FILE *f_unflushed = fopen(inconsistent_write_path, "r");
    if (f_unflushed != NULL) {
      debug("Found %s\n", inconsistent_write_path);
      uint64_t offset;
      uint64_t size;

      while (fscanf(f_unflushed, "%lu %lu", &offset, &size) != EOF) {
        debug("%s offset: %lu, size: %lu\n", inconsistent_write_path, offset, size);

        size_t i = g_validate->inconsistent_info.count++;
        g_validate->inconsistent_info.buffer[i].enabled = 1;
        g_validate->inconsistent_info.buffer[i].offset = offset;
        g_validate->inconsistent_info.buffer[i].size = size;
        g_validate->inconsistent_info.buffer[i].init_sync_value = 0;
      }

      fclose(f_unflushed);
    }
    else {
      fprintf(stderr, "Cannot open %s\n", inconsistent_write_path);
      exit(1);
    }
  } else if (strcmp(inconsistent_write_path, "") == 0) {
    FILE *f_sync = fopen(sync_var_path, "r");
    if (f_sync != NULL) {
      debug("Found %s\n", sync_var_path);
      uint64_t addr;
      uint64_t offset;
      uint64_t size;
      uint64_t val;

      // skip the first line
      fscanf(f_sync, "%*[^\n]\n");
      fscanf(f_sync, "%lx,%lu,%lu,%lu", &addr, &offset, &size, &val);
      debug("%s offset: %lu, size: %lu, val: %lu\n", sync_var_path, offset, size, val);

      size_t i = g_validate->inconsistent_info.count++;
      g_validate->inconsistent_info.buffer[i].enabled = 1;
      g_validate->inconsistent_info.buffer[i].offset = offset;
      g_validate->inconsistent_info.buffer[i].size = size;
      g_validate->inconsistent_info.buffer[i].init_sync_value = val;

      fclose(f_sync);
    }
    else {
      fprintf(stderr, "Cannot open %s\n", sync_var_path);
      exit(1);
    }
  }

  if ((stacktrace_path = getenv("PMRACE_STACKTRACE_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_STACKTRACE_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_STACKTRACE_PATH found: %s\n", stacktrace_path);
  if ((f_stack = fopen(stacktrace_path, "w")) == NULL) {
    fprintf(stderr, "Cannot open %s\n", stacktrace_path);
    exit(1);
  }

  if ((status_path = getenv("PMRACE_STATUS_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_STATUS_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_STATUS_PATH found: %s\n", status_path);

  if (getenv("PMRACE_INSTANCE_ID") == NULL) {
    debug("PMRACE_INSTANCE_ID not found, set to 0\n");
    g_instance_id = 0;
  } else {
    g_instance_id = atoi(getenv("PMRACE_INSTANCE_ID"));
    assert(g_instance_id < _PMRACE_INSTANCE_MAX);
    debug("PMRACE_INSTANCE_ID found: %u\n", g_instance_id);
  }

  assert(atomic_load(&g_shminfo->program_running[g_instance_id]) == 0);

  atomic_store(&g_shminfo->program_running[g_instance_id], 1);
  atomic_store(&main_entered, 1);

  debug("setting main_entered to %d\n", main_entered);
}

void hook_main_exit() {
  // disable hooks after main returns
  atomic_store(&g_shminfo->program_running[g_instance_id], 0);

  // wait a while for the completion of concurrent handlers
  usleep(1000);
  debug("setting program_running[%u] to 0\n", g_instance_id);

  FILE *f_stat = fopen(status_path, "w");
  if (f_stat == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", status_path);
    exit(1);
  }
  fprintf(f_stat, "%d", 0);
  fclose(f_stat);

  int shmid = g_validate->shmid;
  if (shmdt(g_validate) == -1) {
    perror("shmdt 2");
    exit(1);
  }

  shmctl(shmid, IPC_RMID, 0);
}


void hook_cache_flush(uint64_t addr, hval_64_t hval) {}
void hook_pmemobj_tx_begin(uint64_t hval, uint64_t pool_addr) {}
void hook_pmemobj_tx_add_common(uint64_t hval, uint64_t tx_offset_addr, uint64_t tx_size_addr) {}
void hook_pmemobj_tx_end(uint64_t hval) {}
void hook_foo(uint64_t pool_addr, uint64_t b_addr) {}
void hook_branch_enter(hval_64_t hval) {}
void hook_annotation(hval_64_t hval, uint64_t var_addr, uint64_t size, uint64_t val) {}

void hook_mem_read(uint32_t flags, hval_64_t hval, uint64_t addr, uint64_t size) {
  HOOK_HANDLER_BEGIN();

  if (g_validate->inconsistent_info.transformed == 0)
    return;

  FILTER_NON_PM_ACCESS(addr, size)

  struct hook_mc cell;
  uint8_t found_read_inconsistent = 0;
  uint32_t i, j;
  for (i = 0; i < g_validate->inconsistent_info.count; i++) {
    if (g_validate->inconsistent_info.buffer[i].enabled) {
      if (addr < g_validate->inconsistent_info.buffer[i].end &&
          g_validate->inconsistent_info.buffer[i].begin < (addr + size)) {
        g_validate->inconsistent_info.buffer[i].enabled = 0;
        for (j = 0; j < size; j++) {
          ht_hook_mc_has_slot(&g_validate->hook_mc_ht, addr + j, __hook_mc_read_cell, &cell);
          if (cell.stat == PM_DIRTY) {
            found_read_inconsistent = 1;
            goto out;
          }
        }
      }
    }
  }

out:
  if (found_read_inconsistent) {
    report_finding_in_validation(i, hval, addr, size, "True");
  }

}

void hook_mem_write(uint32_t flags, hval_64_t hval, uint64_t addr, uint64_t size) {
  HOOK_HANDLER_BEGIN();

  if (g_validate->inconsistent_info.transformed == 0)
    return;

  FILTER_NON_PM_ACCESS(addr, size)

  uint8_t may_overwrite_inconsistent = 0;
  // abuse the PM_CLEAN to indicate inconsistent data is overwritten
  struct hook_mc cell = {.stat = PM_CLEAN, .pid = 0, .inst = 0};
  uint64_t i, j;
  for (i = 0; i < g_validate->inconsistent_info.count; i++) {
    may_overwrite_inconsistent = 0;
    if (g_validate->inconsistent_info.buffer[i].enabled) {
      if (addr < g_validate->inconsistent_info.buffer[i].end &&
          g_validate->inconsistent_info.buffer[i].begin < (addr + size)) {
        for (j = 0; j < size; j++) {
          if (ht_hook_mc_has_slot(&g_validate->hook_mc_ht,
                                  addr + j,
                                  __hook_mc_set_cell,
                                  &cell)) {
            may_overwrite_inconsistent = 1;
          };
        }
      }
    }

    // check if all bytes in this region are overwritten
    if (may_overwrite_inconsistent) {
      uint64_t num_clean_bytes = 0;
      for (j = g_validate->inconsistent_info.buffer[i].begin;
           j < g_validate->inconsistent_info.buffer[i].end;
           j++) {
        struct hook_mc temp;
        ht_hook_mc_has_slot(&g_validate->hook_mc_ht, j, __hook_mc_read_cell, &temp);
        if (cell.stat == PM_CLEAN) {
          num_clean_bytes++;
        }
      }
      if (num_clean_bytes == g_validate->inconsistent_info.buffer[i].size) {
        uint8_t enabled = 1;
        // CAS to guarantee one stacktrace at most
        if (atomic_compare_exchange_strong(&g_validate->inconsistent_info.buffer[i].enabled,
                                           &enabled,
                                           0)) {
          g_validate->inconsistent_info.buffer[i].enabled = 0;
          debug("disable offset: %lu, size: %lu, [0x%016lx, 0x%016lx)\n",
            g_validate->inconsistent_info.buffer[i].offset,
            g_validate->inconsistent_info.buffer[i].size,
            g_validate->inconsistent_info.buffer[i].begin,
            g_validate->inconsistent_info.buffer[i].end);
          report_finding_in_validation(i, hval, addr, size, "False");
        }
      }
    }

  }
}

// obj_runtime_init
void hook_obj_runtime_init(
  uint64_t pool_addr, uint64_t heap_offset_addr, uint64_t heap_size_addr
) {
  HOOK_HANDLER_BEGIN();

  uint64_t heap_offset = *(uint64_t *)(heap_offset_addr);
  uint64_t heap_size = *(uint64_t *)(heap_size_addr);

  debug("pool_addr: 0x%lx\n", pool_addr);
  debug("heap offset: *(0x%lx) = %lu\n",
    heap_offset_addr, heap_offset);
  debug("heap size: *(0x%lx) = %lu\n",
    heap_size_addr, heap_size);

  // // Dirty hack into the PMEMobjpool.
  // // To confirm the values, we need to check the installed PMDK.
  // const static uint32_t offsetof_heap_offset = 5136; ///< offsetof(PMEMobjpool, heap_offset)
  // const static uint32_t offsetof_heap_size = 6176; ///< offsetof(PMEMobjpool, heap_size)

  uint64_t i = 0;
  for (i = 0; i < PM_POOL_CAND_MAX; i++) {
    if (pm_regions.regions[i].fd == 0) {
      // find an empty entry to store pm region info
      pm_regions.regions[i].begin = pool_addr + heap_offset;
      pm_regions.regions[i].end = pool_addr + heap_offset + heap_size;
      pm_regions.regions[i].fd = UINT32_MAX; // indicate PMDK pools
      pm_regions.regions[i].is_open = 1;

      pm_regions.count++;

      debug("found a pm region [0x%lx, 0x%lx]\n",
        pm_regions.regions[i].begin, pm_regions.regions[i].end);
      break;
    }
  }

  assert(i < PM_POOL_CAND_MAX);
  set_inconsistent_memory(i);
}

// pmem_map_fileU
void hook_pmem_map_fileU(uint64_t pool_addr, uint64_t size_addr) {
  HOOK_HANDLER_BEGIN();

  uint64_t begin_addr = *(uint64_t *)(pool_addr);
  uint64_t size = *(uint64_t *)(size_addr);

  debug("pool_addr: 0x%lx\n", pool_addr);
  debug("size_addr: *(0x%lx) = %lu\n", size_addr, size);

  uint64_t i = 0;
  for (i = 0; i < PM_POOL_CAND_MAX; i++) {
    if (pm_regions.regions[i].fd == 0) {
      // find an empty entry to store pm region info
      pm_regions.regions[i].begin = pool_addr;
      pm_regions.regions[i].end = pool_addr + size;
      pm_regions.regions[i].fd = UINT32_MAX;  // indicate PMDK pools
      pm_regions.regions[i].is_open = 1;

      pm_regions.count++;

      debug("found a pm region [0x%lx, 0x%lx]\n", pm_regions.regions[i].begin,
            pm_regions.regions[i].end);
      break;
    }
  }

  assert(i < PM_POOL_CAND_MAX);
  set_inconsistent_memory(i);
}

// open
void hook_open(const char *path, uint32_t fd) {
  HOOK_HANDLER_BEGIN();

  debug("open %s\n", path);
  if (strstr(path, pm_pool_path_pattern) == NULL) {
    debug("%s does not match %s, skip it\n", path, pm_pool_path_pattern);
    // not match pm pool pattern and skip this call

    return;
  }

  uint32_t i;
  for (i = 0; i < PM_POOL_CAND_MAX; i++) {
    if (pm_pool_cand_fds[i] == 0) {
      debug("allocate fd(%u) for %s\n", fd, path);
      pm_pool_cand_fds[i] = fd;

      return;
    }
  }

  // complain too much candidate opens
  perror("too many calls of open match pm pattern!");
  fprintf(stderr, "pattern: %s, limit: %d\n",
    pm_pool_path_pattern, PM_POOL_CAND_MAX);
}

// mmap
void hook_mmap(uint64_t addr, uint32_t size, uint32_t fd) {
  HOOK_HANDLER_BEGIN();

  debug("hook_mmap [tid-%u] [pid-%u]\n", get_thread_id(), getpid());

  uint64_t i;
  for (i = 0; i < PM_POOL_CAND_MAX && pm_pool_cand_fds[i] > 0; i++) {
    if (pm_pool_cand_fds[i] == fd)
      break;
  }

  debug("hook_mmap: addr=0x%lx size=%u fd=%u fds[i]=%u\n",
    addr, size, fd, pm_pool_cand_fds[i]);
  if (i == PM_POOL_CAND_MAX || pm_pool_cand_fds[i] != fd) {
    // no matched fd for pm pool mapping
    debug("no matched fd for pm pool mapping\n");

    return;
  }

  for (i = 0; i < PM_POOL_CAND_MAX; i++) {
    // one file is possible to be mmapped to multiple locations
    // if (pm_regions.regions[i].fd == fd) {
    //   fprintf(stderr, "fd(%u) is already mapped\n", fd);
    //   return;
    // }
    if (pm_regions.regions[i].fd == 0) {
      // find an empty entry to store pm region info
      pm_regions.regions[i].begin = addr;
      pm_regions.regions[i].end = addr + size;
      pm_regions.regions[i].fd = fd;
      pm_regions.regions[i].is_open = 1;

      pm_regions.count++;

      debug("found a pm region [0x%lx, 0x%lx], fd: %u\n",
        pm_regions.regions[i].begin, pm_regions.regions[i].end, fd);
      break;
    }
  }

  assert(i < PM_POOL_CAND_MAX);
  set_inconsistent_memory(i);
}
