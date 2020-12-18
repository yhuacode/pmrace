#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <error.h>
#include <sys/types.h>

#include "hook_hash.h"
#include "hook_ctrl.h"
#include "hook_mem_access.h"

// #define INST_TRACE_ENABLE 1

void hook_main_enter() {
  debug("enter main\n");
  assert(main_entered == 0);

  // Link coverage data in shared memory
  int shmid = attach_shared_coverage_info();
  if (shmid == -1) {
    perror("hook_main_enter attach");
    exit(1);
  }
  fprintf(stdout, "shmid: %d\n", shmid);

  attach_runtime_info();

  pid_32_t pid = get_thread_id();
  debug("hook_main_enter [tid-%u] [pid-%u]\n", pid, getpid());

  // Initialize reader/writer table
  memset(&g_rtinfo->hook_mc_reader_ht, 0, sizeof(ht_hook_mc_t));
  memset(&g_rtinfo->hook_mc_writer_ht, 0, sizeof(ht_hook_mc_t));

  // Initialize the control block table
  memset(&g_rtinfo->hook_cb_ht, 0, sizeof(ht_hook_cb_t));

  // Initialize the sync var table
  memset(&g_rtinfo->hook_sync_var_ht, 0, sizeof(ht_hook_sync_var_t));

  // Initialize runtime info
  atomic_store(&g_rtinfo->cov_cfg_edge_incr, 0);
  atomic_store(&g_rtinfo->cov_dfg_edge_incr, 0);
  atomic_store(&g_rtinfo->cov_alias_inst_incr, 0);
  atomic_store(&g_rtinfo->sync_var_incr, 0);

  atomic_store(&g_rtinfo->cov_cfg_edge, 0);
  atomic_store(&g_rtinfo->cov_dfg_edge, 0);
  atomic_store(&g_rtinfo->cov_alias_inst, 0);

  memset(&g_rtinfo->bitmaps, 0, sizeof(struct hook_cov_bitmaps));

  if ((g_rtinfo->img_path = getenv("PMEM_POOL")) == NULL) {
    fprintf(stderr, "PMEM_POOL not found\n");
    exit(1);
  }
  debug("PMEM_POOL found: %s\n", g_rtinfo->img_path);

  if ((g_rtinfo->output_dir = getenv("OUTPUT_DIR")) == NULL) {
    fprintf(stderr, "OUTPUT_DIR not found\n");
    exit(1);
  }
  debug("OUTPUT_DIR found: %s\n", g_rtinfo->output_dir);

  if ((g_rtinfo->race_path = getenv("PMRACE_RACE_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_RACE_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_RACE_PATH found: %s\n", g_rtinfo->race_path);

  if ((g_rtinfo->unflushed_path = getenv("PMRACE_UNFLUSHED_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_UNFLUSHED_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_UNFLUSHED_PATH found: %s\n", g_rtinfo->unflushed_path);

  if ((g_rtinfo->cov_path = getenv("PMRACE_COV_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_COV_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_COV_PATH found: %s\n", g_rtinfo->cov_path);

  if ((g_rtinfo->skip_path = getenv("PMRACE_SKIP_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_SKIP_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_SKIP_PATH found: %s\n", g_rtinfo->skip_path);

  if ((g_rtinfo->dfsan_path = getenv("PMRACE_DFSAN_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_DFSAN_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_DFSAN_PATH found: %s\n", g_rtinfo->dfsan_path);

  if ((g_rtinfo->stacktrace_path = getenv("PMRACE_STACKTRACE_PATH")) == NULL) {
    fprintf(stderr, "PMRACE_STACKTRACE_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_STACKTRACE_PATH found: %s\n", g_rtinfo->stacktrace_path);

  char delay_path[256];
  sprintf(delay_path, "%s/delay.txt", g_rtinfo->output_dir);
  FILE *f_delay = fopen(delay_path, "r");
  if (f_delay != NULL) {
    debug("Found a config file for delay injection.\n");
    hval_64_t hval;
    uint32_t delay_us;

    while (fscanf(f_delay, "%lu %u", &hval, &delay_us) != EOF) {
      debug("%s hval: %lu, delay: %u\n", delay_path, hval, delay_us);
      struct hook_im *im_ptr = ht_hook_im_get_slot(&g_rtinfo->hook_delay_ht, hval);
      im_ptr->delay_us = delay_us;
    }

    fclose(f_delay);
  }
  else {
    debug("Delay injection disabled.\n");
  }

  if (getenv("ENABLE_TRACE_ANALYSIS") == NULL) {
    debug("ENABLE_TRACE_ANALYSIS not found\n");
    g_rtinfo->is_trace_enabled = 0;
  } else {
    g_rtinfo->is_trace_enabled = atoi(getenv("ENABLE_TRACE_ANALYSIS"));
    debug("ENABLE_TRACE_ANALYSIS found: %u\n", g_rtinfo->is_trace_enabled);
  }

  // Set SKIP_PM_IMG_BACKUP=1 to disable the PM img backup, thus reducing the
  // space overhead of fuzzing. However, without PM img backups, it is impossible
  // to perform post-failure validation. This environment variable is used for
  // experiments of evaluating the interleaving exploration efficiency.
  if (getenv("SKIP_PM_IMG_BACKUP") == NULL) {
    debug("SKIP_PM_IMG_BACKUP not found\n");
    g_rtinfo->is_img_backup_enabled = 1;
  } else {
    g_rtinfo->is_img_backup_enabled = !atoi(getenv("SKIP_PM_IMG_BACKUP"));
    debug("SKIP_PM_IMG_BACKUP found: (is enabled = %u)\n", g_rtinfo->is_img_backup_enabled);
  }

  if (getenv("PMRACE_INSTANCE_ID") == NULL) {
    debug("PMRACE_INSTANCE_ID not found, set to 0\n");
    g_instance_id = 0;
  } else {
    g_instance_id = atoi(getenv("PMRACE_INSTANCE_ID"));
    assert(g_instance_id < _PMRACE_INSTANCE_MAX);
    debug("PMRACE_INSTANCE_ID found: %u\n", g_instance_id);
  }

  /**
   * The format for sync configuration file
   *  each line: hval,type('r'/'w'),skip
   */
  char *sync_config_path = getenv("PMRACE_SYNC_CONFIG_PATH");
  if (sync_config_path == NULL) {
    fprintf(stderr, "PMRACE_SYNC_CONFIG_PATH not found\n");
    exit(1);
  }
  debug("PMRACE_SYNC_CONFIG_PATH found: %s\n", sync_config_path);

  FILE *f_sync = fopen(sync_config_path, "r");
  if (f_sync != NULL) {
    uint64_t hval;
    char c;
    uint32_t skip, point_num, thread_num, count = 0;

    if (fscanf(f_sync, "%u %u", &point_num, &thread_num) != 2) {
      fprintf(stderr, "error for %s format\n", sync_config_path);
      exit(1);
    }
    assert(point_num <= _SYNC_POINTS_MAX);

    g_rtinfo->sync.m = 0;
    g_rtinfo->sync.waiting_readers = 0;
    g_rtinfo->sync.has_privileged_reader = 0;
    g_rtinfo->sync.total_disabled = 0;
    g_rtinfo->sync.point_num = point_num;
    g_rtinfo->sync.thread_num = thread_num;

    if (point_num > 0) {
      srand((unsigned)time(NULL));
      g_rtinfo->sync.allowed_reader = rand() % thread_num;
      debug("sync: allowed_reader %u, thread_num %u\n",
        g_rtinfo->sync.allowed_reader, thread_num);

      debug("found %u lines in %s\n", point_num, sync_config_path);

      while (fscanf(f_sync, "%lu %c %u", &hval, &c, &skip) != EOF &&
            count < point_num
      ) {
        g_rtinfo->sync.pts[count].hval = hval;
        g_rtinfo->sync.pts[count].type = c;
        g_rtinfo->sync.pts[count].skip = skip;
        g_rtinfo->sync.pts[count].is_enabled = 1;
        debug("sync: %lu(hval) %c(type) %u(skip)\n", hval, c, skip);
        count ++;
      }
    }

    fclose(f_sync);
  }
  else {
    debug("%s not found, sync exploration disabled.\n", sync_config_path);
  }


  // Initialize g_new_races
  // g_new_races = (struct hook_pair_records*)malloc(sizeof(struct hook_pair_records));
  // if (g_new_races == NULL) {
  //   perror("Hook: g_new_races allocation fails!\n");
  //   exit(1);
  // }
  memset(&g_rtinfo->new_races, 0, sizeof(struct hook_pair_records));

  // Initialize g_new_memdu
  // g_new_memdu = (struct hook_pair_records*)malloc(sizeof(struct hook_pair_records));
  // if (g_new_memdu == NULL) {
  //   perror("Hook: g_new_memdu allocation fails!\n");
  //   exit(1);
  // }
  // memset(g_new_memdu, 0, sizeof(struct hook_pair_records));
  memset(&g_rtinfo->new_memdu, 0, sizeof(struct hook_pair_records));

  // Initialize curr_races and curr_memdu
  memset(&g_rtinfo->curr_races, 0, sizeof(struct hook_pair_records));
  memset(&g_rtinfo->curr_memdu, 0, sizeof(struct hook_pair_records));

  // // Initialize sync_hints
  // memset(&g_rtinfo->sync_hints, 0, sizeof(struct hook_annotation_records));

  // Pre-allocation of log handlers to make them visible
  // to children threads/processes. Children processes inherit
  // the fds of their parent process.

  char log_dir[1024];
  // skip the suffix of "---cov"
  snprintf(log_dir, strlen(g_rtinfo->cov_path) - 5, "%s", g_rtinfo->cov_path);
  struct stat st = {0};
  if (stat(log_dir, &st) == -1) {
    mkdir(log_dir, 0775);
  }

  uint32_t i;
  for (i = 0; i < _LOG_HANDLER_MAX; i++) {
    char log_path[1024];
    sprintf(log_path, "%s/%u.log", log_dir, i);
    g_rtinfo->logs.handlers[i].out = fopen(log_path, "w+");
    // g_rtinfo->logs.handlers[i].out = tmpfile();
  }

  assert(atomic_load(&g_shminfo->program_running[g_instance_id]) == 0);

  atomic_store(&g_shminfo->program_running[g_instance_id], 1);
  atomic_store(&main_entered, 1);

  debug("setting main_entered to %d\n", main_entered);
}


void hook_main_exit() {
  debug("exit main\n");
  assert(atomic_load(&g_shminfo->program_running[g_instance_id]) == 1);

  // disable hooks after main returns
  atomic_store(&g_shminfo->program_running[g_instance_id], 0);

  // wait a while for the completion of concurrent handlers
  usleep(1000);
  debug("setting program_running[%u] to 0\n", g_instance_id);

  // free(g_hook_mc_reader_ht);
  // g_hook_mc_reader_ht = NULL;

  // free(g_hook_mc_writer_ht);
  // g_hook_mc_writer_ht = NULL;

  // free(g_hook_cb_ht);
  // g_hook_cb_ht = NULL;

  FILE *f_skip = fopen(g_rtinfo->skip_path, "w");
  if (f_skip == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", g_rtinfo->skip_path);
    exit(1);
  }

  int i;
  for (i = 0; i < g_rtinfo->sync.point_num; i++) {
    if (g_rtinfo->sync.pts[i].type == MEM_READ &&
        g_rtinfo->sync.pts[i].is_enabled == 0) {
      fprintf(f_skip, "%lu\n", g_rtinfo->sync.pts[i].hval);
    }
  }
  fclose(f_skip);
  debug("skipped insts are stored in %s\n", g_rtinfo->skip_path);
  // free(g_rtinfo->sync.ptr);
  // g_rtinfo->sync.ptr = NULL;

  if (g_rtinfo->dfsan_records.count > 0) {
    FILE *f_dfsan = fopen(g_rtinfo->dfsan_path, "w");
    fprintf(f_dfsan, "id,pid,flags,ruhash,addr,size,offset,hval\n");
    for (i = 0; i < g_rtinfo->dfsan_records.count; i++) {
      fprintf(f_dfsan, "dfsan-%u,%u,%u,%s,0x%016lx,%lu,%lu,%lu\n",
        g_rtinfo->dfsan_records.buffer[i].id,
        g_rtinfo->dfsan_records.buffer[i].pid,
        g_rtinfo->dfsan_records.buffer[i].flags,
        g_rtinfo->dfsan_records.buffer[i].hash_str,
        g_rtinfo->dfsan_records.buffer[i].addr,
        g_rtinfo->dfsan_records.buffer[i].size,
        g_rtinfo->dfsan_records.buffer[i].offset,
        g_rtinfo->dfsan_records.buffer[i].hval);
    }
    fclose(f_dfsan);
    debug("dfsan records are stored in %s\n", g_rtinfo->dfsan_path);
  }

  FILE *f_stacktrace = fopen(g_rtinfo->stacktrace_path, "w");
  if (f_stacktrace == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", g_rtinfo->stacktrace_path);
    exit(1);
  }
  combine_all_traces(f_stacktrace);

  pid_32_t pid = get_thread_id();

  /* save new race pairs in file */
  debug("found new race pairs: %lu [tid-%u] [pid-%u]\n",
    atomic_load(&g_rtinfo->new_races.count), pid, getpid());
  FILE *f_race = fopen(g_rtinfo->race_path, "w+");
  if (f_race == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", g_rtinfo->race_path);
    exit(1);
  }

  fprintf(f_race, "tag,pid1,pid2,hash,addr,size,src,dst\n");
  uint64_t idx;
  // const char *type_str = "";
  for(idx = 0; idx < atomic_load(&g_rtinfo->new_races.count); idx++) {
// #ifdef HOOK_DEBUG
//     switch (g_new_races->buffer[idx].type)
//     {
//       case XRW_PAIR:
//         type_str = "[XRW]: ";
//         break;
//       case UWR_PAIR:
//         type_str = "[UWR]: ";
//         break;
//       case XWW_PAIR:
//         type_str = "[XWW]: ";
//         break;
//       case PWR_PAIR:
//         type_str = "[PWR]: ";
//         break;
//       default:
//         perror("wrong race type");
//         exit(1);
//     }
// #endif

    // switch (g_new_races->buffer[idx].type)
    // {
    //   case XRW_PAIR:
    //     fprintf(f_race, "XRW,");
    //     break;
    //   case UWR_PAIR:
    //     fprintf(f_race, "UWR,");
    //     break;
    //   case XWW_PAIR:
    //     fprintf(f_race, "XWW,");
    //     break;
    //   case PWR_PAIR:
    //     fprintf(f_race, "PWR,");
    //     break;
    //   default:
    //     perror("wrong race type");
    //     exit(1);
    // }

    debug("[%s] pid1 = %u, pid2 = %u, hash = %u, "
      "addr = 0x%016lx, size = %u, from = %lu, into = %lu\n",
      pair_type_str[g_rtinfo->new_races.buffer[idx].type],
      g_rtinfo->new_races.buffer[idx].pid1,
      g_rtinfo->new_races.buffer[idx].pid2,
      g_rtinfo->new_races.buffer[idx].hash,
      g_rtinfo->new_races.buffer[idx].addr,
      g_rtinfo->new_races.buffer[idx].size,
      g_rtinfo->new_races.buffer[idx].from,
      g_rtinfo->new_races.buffer[idx].into);

    // if (g_rtinfo->new_races.buffer[idx].type == UWR_PAIR) {
    //   fprintf(stderr, "[PM inter-thread inconsistency bug] read unflushed: "
    //     "0x%016lx(addr) %u(size) %lu(W) %lu(R)\n",
    //     g_rtinfo->new_races.buffer[idx].addr,
    //     g_rtinfo->new_races.buffer[idx].size,
    //     g_rtinfo->new_races.buffer[idx].from,
    //     g_rtinfo->new_races.buffer[idx].into);
    // }

    fprintf(f_race, "%s,%u,%u,alias-%u,0x%016lx,%u,%lu,%lu\n",
      pair_type_str[g_rtinfo->new_races.buffer[idx].type],
      g_rtinfo->new_races.buffer[idx].pid1,
      g_rtinfo->new_races.buffer[idx].pid2,
      g_rtinfo->new_races.buffer[idx].hash,
      g_rtinfo->new_races.buffer[idx].addr,
      g_rtinfo->new_races.buffer[idx].size,
      g_rtinfo->new_races.buffer[idx].from,
      g_rtinfo->new_races.buffer[idx].into);
  }
  fclose(f_race);
  debug("new race pairs are stored in %s\n", g_rtinfo->race_path);

  /* save current race pairs in file */
  debug("found race pairs: %lu [tid-%u] [pid-%u]\n",
    atomic_load(&g_rtinfo->curr_races.count), pid, getpid());
  char curr_race_path[_PATHNAME_MAX];
  assert(strlen(g_rtinfo->race_path) + 10 < _PATHNAME_MAX);
  strcpy(curr_race_path, g_rtinfo->race_path);
  strcat(curr_race_path, ".curr.csv");
  FILE *f_curr_race = fopen(curr_race_path, "w+");
  if (f_curr_race == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", curr_race_path);
    exit(1);
  }

  fprintf(f_curr_race, "tag,pid1,pid2,hash,addr,size,src,dst\n");
  for(idx = 0; idx < atomic_load(&g_rtinfo->curr_races.count); idx++) {
    fprintf(f_curr_race, "%s,%u,%u,alias-%u,0x%016lx,%u,%lu,%lu\n",
      pair_type_str[g_rtinfo->curr_races.buffer[idx].type],
      g_rtinfo->curr_races.buffer[idx].pid1,
      g_rtinfo->curr_races.buffer[idx].pid2,
      g_rtinfo->curr_races.buffer[idx].hash,
      g_rtinfo->curr_races.buffer[idx].addr,
      g_rtinfo->curr_races.buffer[idx].size,
      g_rtinfo->curr_races.buffer[idx].from,
      g_rtinfo->curr_races.buffer[idx].into);
  }
  fclose(f_curr_race);
  debug("current race pairs are stored in %s\n", curr_race_path);

  // free(g_new_races);
  // g_new_races = NULL;

  /* save new memdus in file */
  debug("found new memdu cases: %lu [tid-%u] [pid-%u]\n",
    atomic_load(&g_rtinfo->new_memdu.count), pid, getpid());
  FILE *f_unflushed = fopen(g_rtinfo->unflushed_path, "w+");
  if (f_unflushed == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", g_rtinfo->unflushed_path);
    exit(1);
  }

  fprintf(f_unflushed, "tag,pid1,pid2,hash,addr,size,src,dst\n");
  for (idx = 0; idx < atomic_load(&g_rtinfo->new_memdu.count); idx++) {
    debug("[%s] %u(pid1) %u(pid2) %u(hash) 0x%016lx(addr) %u(size) %lu(W) %lu(R)\n",
      pair_type_str[g_rtinfo->new_memdu.buffer[idx].type],
      g_rtinfo->new_memdu.buffer[idx].pid1,
      g_rtinfo->new_memdu.buffer[idx].pid2,
      g_rtinfo->new_memdu.buffer[idx].hash,
      g_rtinfo->new_memdu.buffer[idx].addr,
      g_rtinfo->new_memdu.buffer[idx].size,
      g_rtinfo->new_memdu.buffer[idx].from,
      g_rtinfo->new_memdu.buffer[idx].into);

    fprintf(f_unflushed, "%s,%u,%u,memdu-%u,0x%016lx,%u,%lu,%lu\n",
      pair_type_str[g_rtinfo->new_memdu.buffer[idx].type],
      g_rtinfo->new_memdu.buffer[idx].pid1,
      g_rtinfo->new_memdu.buffer[idx].pid2,
      g_rtinfo->new_memdu.buffer[idx].hash,
      g_rtinfo->new_memdu.buffer[idx].addr,
      g_rtinfo->new_memdu.buffer[idx].size,
      g_rtinfo->new_memdu.buffer[idx].from,
      g_rtinfo->new_memdu.buffer[idx].into);
  }
  fclose(f_unflushed);
  debug("new intra-thread read unflushed are stored in %s\n",
    g_rtinfo->unflushed_path);

  /* save current memdus in file */
  debug("found memdu cases: %lu [tid-%u] [pid-%u]\n",
    atomic_load(&g_rtinfo->curr_memdu.count), pid, getpid());
  char curr_unflushed_path[_PATHNAME_MAX];
  assert(strlen(g_rtinfo->unflushed_path) + 10 < _PATHNAME_MAX);
  strcpy(curr_unflushed_path, g_rtinfo->unflushed_path);
  strcat(curr_unflushed_path, ".curr.csv");
  FILE *f_curr_unflushed = fopen(curr_unflushed_path, "w+");
  if (f_curr_unflushed == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", curr_unflushed_path);
    exit(1);
  }

  fprintf(f_curr_unflushed, "tag,pid1,pid2,hash,addr,size,src,dst\n");
  for (idx = 0; idx < atomic_load(&g_rtinfo->curr_memdu.count); idx++) {
    fprintf(f_curr_unflushed, "%s,%u,%u,memdu-%u,0x%016lx,%u,%lu,%lu\n",
      pair_type_str[g_rtinfo->curr_memdu.buffer[idx].type],
      g_rtinfo->curr_memdu.buffer[idx].pid1,
      g_rtinfo->curr_memdu.buffer[idx].pid2,
      g_rtinfo->curr_memdu.buffer[idx].hash,
      g_rtinfo->curr_memdu.buffer[idx].addr,
      g_rtinfo->curr_memdu.buffer[idx].size,
      g_rtinfo->curr_memdu.buffer[idx].from,
      g_rtinfo->curr_memdu.buffer[idx].into);
  }
  fclose(f_curr_unflushed);
  debug("current intra-thread read unflushed are stored in %s\n",
    curr_unflushed_path);

  // fprintf(stderr, "sync var hints: addr, size, val\n");
  // for (idx = 0; idx < atomic_load(&g_rtinfo->sync_hints.count); idx++) {
  //   fprintf(stderr, "\t0x%lx, %lu, %lu\n",
  //     g_rtinfo->sync_hints.buffer[idx].addr,
  //     g_rtinfo->sync_hints.buffer[idx].size,
  //     g_rtinfo->sync_hints.buffer[idx].val);
  // }

  // free(g_new_memdu);
  // g_new_memdu = NULL;

  // save the coverage info in files
  debug("cov_cfg_edge: %lu\n", g_rtinfo->cov_cfg_edge);
  debug("cov_dfg_edge: %lu\n", g_rtinfo->cov_dfg_edge);
  debug("cov_alias_inst: %lu\n", g_rtinfo->cov_alias_inst);

  debug("cov_cfg_edge_incr: %lu\n", g_rtinfo->cov_cfg_edge_incr);
  debug("cov_dfg_edge_incr: %lu\n", g_rtinfo->cov_dfg_edge_incr);
  debug("cov_alias_inst_incr: %lu\n", g_rtinfo->cov_alias_inst_incr);

  FILE *f_cov = fopen(g_rtinfo->cov_path, "w+");
  if (f_cov == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", g_rtinfo->cov_path);
    exit(1);
  }

  fprintf(f_cov, "%lu,%lu,%lu\n%lu,%lu,%lu",
    g_rtinfo->cov_cfg_edge,
    g_rtinfo->cov_dfg_edge,
    g_rtinfo->cov_alias_inst,
    g_rtinfo->cov_cfg_edge_incr,
    g_rtinfo->cov_dfg_edge_incr,
    g_rtinfo->cov_alias_inst_incr);
  fclose(f_cov);
  debug("coverage info is stored in %s\n", g_rtinfo->cov_path);

  char stat_path[256];
  sprintf(stat_path, "%s/stat", g_rtinfo->output_dir);
  FILE *f_stat = fopen(stat_path, "w");
  if (f_stat == NULL) {
    perror("can not open output directory");
    fprintf(stderr, "%s is unavailable\n", stat_path);
    exit(1);
  }
  fprintf(f_stat, "%d", 0);
  fclose(f_stat);

  debug("freeing all thread control blocks\n");
  ht_hook_cb_for_each(&g_rtinfo->hook_cb_ht, __hook_cb_free, NULL);

  // free(g_rtinfo);
  // g_rtinfo = NULL;

  detach_shared_coverage_info();
}


// Alias coverage (load)
void hook_mem_read(
#ifdef INST_TRACE_ENABLE
  uint32_t flags, hval_64_t hval, uint64_t addr, uint64_t size,
  char *repr, char *loc
#else
  uint32_t flags, hval_64_t hval, uint64_t addr, uint64_t size
#endif
) {
  HOOK_HANDLER_BEGIN()

#ifdef INST_TRACE_ENABLE
  debug("read  0x%016lx, %lu(size), %lu(hval), %u(flags)\n%s\n[%s]\n",
    addr, size, hval, flags, repr, loc);
#endif

  if (flags > 3) {
    debug("error on flags\n");
  }

  pid_32_t pid = get_thread_id();
  struct hook_cb *cb = hook_cb_get_or_create(pid);

  // debug("[thread-%d] DEBUG read 0x%016lx, %lu(size), %lu(hval)\n", pid, addr,
  // size, hval);

  FILTER_NON_PM_ACCESS(addr, size)

  struct hook_im *im_ptr = ht_hook_im_has_slot(&g_rtinfo->hook_delay_ht, hval);
  if (im_ptr && im_ptr->delay_us > 0) {
    debug("delay injection(%u us), read  0x%016lx, %lu(hval)\n",
      im_ptr->delay_us, addr, hval);
    usleep(im_ptr->delay_us);
  }

  uint64_t i;
  uint32_t in_sync = 0;
  for (i = 0; i < g_rtinfo->sync.point_num; i++) {
    if (cb->bypass_reader_sync == 0 &&
        g_rtinfo->sync.pts[i].is_enabled &&
        g_rtinfo->sync.pts[i].hval == hval &&
        g_rtinfo->sync.pts[i].type == MEM_READ) {
      in_sync = 1;
      break;
    }
  }
  if (in_sync) {
    if (g_rtinfo->sync.pts[i].skip == 0) {
      debug("[thread-%u] reader waits in 0x%016lx, %lu(hval)\n",
        pid, addr, hval);

      if (cb->reader_id == 0) {
        cb->reader_id = atomic_fetch_add(&g_rtinfo->sync.waiting_readers, 1);
        debug("[thread-%u] reader increases waiting_readers from %u\n",
          pid, cb->reader_id);
      }
      uint32_t thread_num = g_rtinfo->sync.thread_num;

      uint32_t spin_count = 0;
      while (!atomic_load(&g_rtinfo->sync.m)) {
        usleep(100);
        spin_count++;

        // If one thread has been waiting for a long time, an unnecessary
        // synchronization point may exist. As a result, we disable current
        // point and increase the skip for future runs.
        if (spin_count == 1000) {
          // atomic_fetch_sub(&g_rtinfo->sync.waiting_readers, 1);
          g_rtinfo->sync.pts[i].is_enabled = 0;
          uint64_t old_v = atomic_fetch_add(&g_rtinfo->sync.total_disabled, 1);
          debug("[thread-%u] reader disables %lu(hval), total_disabled: %lu\n",
            pid, hval, old_v + 1);
          break;
        }
        // If all threads block in injected breakpoints for readers,
        // randomly select one reader thread to bypass reader breakpoints.
        if (g_rtinfo->sync.allowed_reader == cb->reader_id &&
          atomic_load(&g_rtinfo->sync.waiting_readers) == thread_num) {
          atomic_store(&g_rtinfo->sync.has_privileged_reader, 1);
          cb->bypass_reader_sync = 1;
          debug("[thread-%u] reader is allowed to continue\n", pid);
          break;
        }
      }
      if (spin_count < 1000) {
        debug("[thread-%u] reader resumes in 0x%016lx, %lu(hval)\n",
          pid, addr, hval);
      }
      else {
        // cb->bypass_reader_sync = 1;
        debug("[thread-%u] reader hangs in 0x%016lx, %lu(hval)\n",
          pid, addr, hval);
      }
    } else {
      debug("[thread-%u] reader skips sync point in 0x%016lx, %lu(hval), %u(skip)\n",
        pid, addr, hval, g_rtinfo->sync.pts[i].skip);
      g_rtinfo->sync.pts[i].skip--;
    }
  }

  // A memory cell for a one-byte region in PM
  struct hook_mc cell;

  // The hval of last load/store insturction of ANOTHER thread
  // for alias pairs. (0 indicates the absence of such instructions)
  hval_64_t p;
  // The hval of last load/store insturction of THIS thread
  // for memdu pairs. (0 indicates the absence of such instructions)
  hval_64_t s;

  // The thread id of last accessing thread
  pid_32_t p_pid;
  // The last p_pid for read-read alias pair. The value of "pr_pid" is
  // updated when a new load instruction is found in the memory region
  // to be iterated.
  pid_32_t pr_pid = 0;
  // The last p_pid for write-read alias pair. The value of "pw_pid" is
  // updated when a new store instruction is found or the alias type
  // changes from PWR_PAIR to PWR_PAIR in the memory region to be iterated.
  pid_32_t pw_pid = 0;

  /*
    The cursors in the memory region and corresponding hvals of last
    load/store instruction.

      ar_cur: the cursor of read-read alias checking
      pr_cur: the hval of corresponding last load instruction (i.e., "p")

      aw_cur: the cursor of write-read alias checking
      pw_cur: the hval of corresponding last store instruction (i.e., "p")

      mr_cur: the cursor of read-read memdu checking
      sr_cur: the hval of corresponding last load instruction (i.e., "s")

      mw_cur: the cursor of write-read memdu checking
      sw_cur: the hval of corresponding last store instruction (i.e., "s")
  */
  ALIAS_CHECK_DECLARE(ar_cur, pr_cur)
  ALIAS_CHECK_DECLARE(aw_cur, pw_cur)
  MEMDU_CHECK_DECLARE(mr_cur, sr_cur)
  MEMDU_CHECK_DECLARE(mw_cur, sw_cur)

  /* init the cursors and hvals */
  ALIAS_CHECK_INIT(ar_cur, pr_cur)
  ALIAS_CHECK_INIT(aw_cur, pw_cur)
  MEMDU_CHECK_INIT(mr_cur, sr_cur)
  MEMDU_CHECK_INIT(mw_cur, sw_cur)

  // The memdu pair type of current memory cell
  pair_type_t mt;
  // The alias pair type of current memory cell
  pair_type_t rt;

  // The memdu pair type (persistency) of the memory cell of
  // the write-read cursor in this memory region
  pair_type_t mtw_cur = PWR_PAIR;

  // The alias pair type (persistency) of the memory cell of
  // the write-read cursor in this memory region
  pair_type_t rtw_cur = PWR_PAIR;

  // indicate whether data is added in tx
  uint8_t in_tx = 0;

  debug("[thread-%d] pm read  0x%016lx, %lu(size), %lu(hval)\n", pid, addr,
        size, hval);

  for (i = 0; i < size; i++) {
    /* check PM alias instriction pair (read-read) */
    mem_check_alias_reader(cb->pid, hval, addr + i, &s, &p, &p_pid);

    // check if we need to report XRR alias pair
    ALIAS_CHECK_LOOP(cb, hval, p_pid, addr, i, p, ar_cur, pr_cur, pr_pid, XRR_PAIR)

    // check if we need to report XRR memdu pair
    MEMDU_CHECK_LOOP(cb, hval, addr, i, s, mr_cur, sr_cur, XRR_PAIR)

    in_tx = is_added_in_tx(cb, addr + i);

    /* check PM alias instriction pair (write-read) */
    mem_check_alias_writer_for_reader(
      cb->pid, hval, addr + i, &s, &p, &mt, &rt, &cell, &p_pid, in_tx);

    // check if we need to record UWR alias pair
    if (pw_cur != p || (rtw_cur == PWR_PAIR && rt == UWR_PAIR)) {
      if (pw_cur) {
        cov_alias_add_pair(
          cb, hash_triple_u64_into_h24(pw_cur, hval, rtw_cur), pw_pid,
          pw_cur, hval, addr + aw_cur, i - aw_cur + 1, rtw_cur);
      }
      pw_pid = p_pid;
      pw_cur = p;
      aw_cur = i;
      rtw_cur = rt;
    }

    // check if we need to report UWR memdu pair
    if (sw_cur != s || (mtw_cur == PWR_PAIR && mt == UWR_PAIR)) {
      if (sw_cur) {
        cov_dfg_add_edge(
          cb, hash_triple_u64_into_h24(sw_cur, hval, mtw_cur),
          sw_cur, hval, addr + mw_cur, i - mw_cur + 1, mtw_cur);
      }
      sw_cur = s;
      mw_cur = i;
      mtw_cur = mt;
    }

    /* set the access info */
    cell.stat = PM_UNDETERMINED;
    cell.pid = cb->pid;
    cell.inst = hval;

    /*
     * take ownership of the cell
     *
     * Note that following execution of 'ht_hook_mc_get_slot'
     * only ensures the atomicity of cell modifications (i.e.,
     * '__hook_mc_set_cell'). Checking writers and updating
     * readers access two different tables, which are not
     * atomic.
     *
     * For concurrent execution, it's possible that a reader
     * and a writer with same address fail to know each other.
     * An example is as follows.
     *
     *    Reader: check writers                     set reader
     *    Writer:                 checker reader    set writer
     *
     * However, with enough executions in fuzzing, most alias
     * pairs would be found.
     */
    // ht_hook_mc_get_slot(g_hook_mc_reader_ht, addr + i, __hook_mc_set_cell, &cell);
    ht_hook_mc_get_slot(&g_rtinfo->hook_mc_reader_ht, addr + i, __hook_mc_set_cell, &cell);
  }

  /* Flush alias/memdu pairs at the end of iteration */
  ALIAS_CHECK_FINI(cb, hval, addr, size, ar_cur, pr_cur, pr_pid, XRR_PAIR)
  ALIAS_CHECK_FINI(cb, hval, addr, size, aw_cur, pw_cur, pw_pid, rtw_cur)
  MEMDU_CHECK_FINI(cb, hval, addr, size, mr_cur, sr_cur, XRR_PAIR)
  MEMDU_CHECK_FINI(cb, hval, addr, size, mw_cur, sw_cur, mtw_cur)
}


// Alias coverage (store)
void hook_mem_write(
#ifdef INST_TRACE_ENABLE
  uint32_t is_non_temporal, hval_64_t hval, uint64_t addr, uint64_t size,
  const char *repr, const char *loc
#else
  uint32_t is_non_temporal, hval_64_t hval, uint64_t addr, uint64_t size
#endif
) {
  HOOK_HANDLER_BEGIN()

#ifdef INST_TRACE_ENABLE
  debug("write 0x%016lx, %lu(size), %lu(hval), %u(is_non_temporal)\n%s\n[%s]\n",
    addr, size, hval, is_non_temporal, repr, loc);
#endif

  pid_32_t pid = get_thread_id();
  struct hook_cb *cb = hook_cb_get_or_create(pid);

  // debug("[thread-%d] DEBUG write 0x%016lx, %lu(size), %lu(hval)\n", pid,
  // addr,
  //       size, hval);

  FILTER_NON_PM_ACCESS(addr, size)

  /* check persisted synchronization */
  struct hook_sync_var *sv;
  if ((sv = ht_hook_sync_var_has_slot(&g_rtinfo->hook_sync_var_ht, addr, NULL, NULL))) {
    // debug("new sync inst (1): hval = %lu, addr = %lu, size = %lu, val = %lu\n",
    //   hval, addr, sv->size, sv->val);
    /* skip stores that do not change lock values */
    switch (sv->size)
    {
    case 1:
    {
      uint8_t data = *((uint8_t *)(addr));
      if (data == sv->val) {
        // debug("sync inst: init sync var to %lu (uint8)\n", sv->val);
        return;
      }
      break;
    }

    case 2:
    {
      uint16_t data = *((uint16_t *)(addr));
      if (data == sv->val) {
        // debug("sync inst: init sync var to %lu (uint16)\n", sv->val);
        return;
      }
      break;
    }

    case 4:
    {
      uint32_t data = *((uint32_t *)(addr));
      if (data == sv->val) {
        // debug("sync inst: init sync var to %lu (uint32)\n", sv->val);
        return;
      }
      break;
    }

    case 8:
    {
      uint64_t data = *((uint64_t *)(addr));
      if (data == sv->val) {
        // debug("sync inst: init sync var to %lu (uint64)\n", sv->val);
        return;
      }
      break;
    }

    default:
      break;
    }

    /* check if the sync var is tested */
    if (!test_and_set_bit(hash_u64_into_h24(sv->offset), g_shminfo->sync_var_record)) {
    // hash24_t hx1 = hash_u64_into_h24(sv->offset);
    // debug("xxxxxxx: hx1 = %lu\n", hx1);
    // if (!test_and_set_bit(hx1, g_shminfo->sync_var_record)) {
      /* check if the store instruction modifying sync var is tested */
      if (!test_and_set_bit(hash_u64_into_h24(hval), g_shminfo->sync_inst)) {
      // hash24_t hx2 = hash_u64_into_h24(hval);
      // debug("xxxxxxx: hx2 = %lu\n", hx2);
      // if (!test_and_set_bit(hx2, g_shminfo->sync_inst)) {
        debug("new sync inst: hval = %lu, addr = %lu\n", hval, addr);

        uint64_t img_id = atomic_fetch_add(&g_rtinfo->sync_var_incr, 1);

        DO_BACKUP_IMG("sync", img_id)

        char sync_var_path[512];
        sprintf(sync_var_path, "%s/sync-%lu.txt", backup_img_dir, img_id);
        FILE *f_sync_var = fopen(sync_var_path, "w");
        fprintf(f_sync_var, "addr,offset,size,val\n0x%lx,%lu,%lu,%lu\n",
          sv->addr, sv->offset, sv->size, sv->val);
        fclose(f_sync_var);

#ifdef STACK_TRACE_ENABLE
        fprintf(cb->trace_stream, "hash: sync-%lu\n", img_id);
        fprintf(cb->trace_stream, "sync: %lu(W) 0x%016lx(addr)\n", hval, addr);
        printStackTrace(cb->trace_stream, 1);
#endif
      }
    }

    // no further checking of inconsistency.
    return;
  }

  /* check memdu and alias */
  struct hook_im *im_ptr = ht_hook_im_has_slot(&g_rtinfo->hook_delay_ht, hval);
  if (im_ptr && im_ptr->delay_us > 0) {
    debug("delay injection(%u us), write 0x%016lx, %lu(hval)\n",
      im_ptr->delay_us, addr, hval);
    usleep(im_ptr->delay_us);
  }

  uint64_t i;

  // A memory cell for a one-byte region in PM
  struct hook_mc cell;

  // The hval of last load/store insturction of ANOTHER thread
  // for alias pairs. (0 indicates the absence of such instructions)
  hval_64_t p;
  // The hval of last load/store insturction of THIS thread
  // for memdu pairs. (0 indicates the absence of such instructions)
  hval_64_t s;

  // The thread id of last accessing thread
  pid_32_t p_pid;
  // The last p_pid for read-write alias pair. The value of "pr_pid" is
  // updated when a new load instruction is found in the memory region
  // to be iterated.
  pid_32_t pr_pid = 0;
  // The last p_pid for write-write alias pair. The value of "pw_pid" is
  // updated when a new store instruction is found in the memory region
  // to be iterated.
  pid_32_t pw_pid = 0;

  /*
    The cursors in the memory region and corresponding hvals of last
    load/store instruction.

      ar_cur: the cursor of read-write alias checking
      pr_cur: the hval of corresponding last load instruction (i.e., "p")

      aw_cur: the cursor of write-write alias checking
      pw_cur: the hval of corresponding last store instruction (i.e., "p")

      mr_cur: the cursor of read-write memdu checking
      sr_cur: the hval of corresponding last load instruction (i.e., "s")

      mw_cur: the cursor of write-write memdu checking
      sw_cur: the hval of corresponding last store instruction (i.e., "s")
  */
  ALIAS_CHECK_DECLARE(ar_cur, pr_cur)
  ALIAS_CHECK_DECLARE(aw_cur, pw_cur)
  MEMDU_CHECK_DECLARE(mr_cur, sr_cur)
  MEMDU_CHECK_DECLARE(mw_cur, sw_cur)

  debug("[thread-%d] %u(%s) pm write 0x%016lx, %lu(size), %lu(hval)\n", pid,
        is_non_temporal, is_non_temporal == 1 ? "is NT" : "not NT", addr, size, hval);

#ifdef HOOK_DEBUG
  uint64_t offset;
  for (i = 0; i < pm_regions.count; i++) {
    if (pm_regions.regions[i].is_open) {
      if (addr >= pm_regions.regions[i].begin
        && (addr + size) <= pm_regions.regions[i].end) {
        offset = addr - pm_regions.regions[i].begin;
        break;
      }
    }
  }

#endif

  /* record pm writes based on reading unflushed */
  dfsan_label content_label = dfsan_read_label((void*)addr,(size_t)size);
  dfsan_label address_label = dfsan_get_label(addr);
  struct unflushed_data *unflushed_cur, *unflushed_prev = NULL;
  for (unflushed_cur = cb->unflushed_data_head;
      unflushed_cur != NULL;
      ) {
    uint32_t dfsan_flag = 0;
    if (dfsan_has_label(content_label, unflushed_cur->label)) {
      // inconsistent content based on reading unflushed
      // i.e., writing unreliable content
      dfsan_flag = 1;
    } else if (dfsan_has_label(address_label, unflushed_cur->label)) {
      // inconsistent address based on reading unflushed
      // i.e., writing to wrong address
      dfsan_flag = 2;
    }

    if (dfsan_flag != 0) {
      uint64_t rid = atomic_fetch_add(&g_rtinfo->dfsan_records.count, 1);
      memcpy(g_rtinfo->dfsan_records.buffer[rid].hash_str, unflushed_cur->hash_str,
        sizeof(unflushed_cur->hash_str));
      g_rtinfo->dfsan_records.buffer[rid].id = rid;
      g_rtinfo->dfsan_records.buffer[rid].pid = pid;
      g_rtinfo->dfsan_records.buffer[rid].flags = dfsan_flag;
      g_rtinfo->dfsan_records.buffer[rid].addr = addr;
      g_rtinfo->dfsan_records.buffer[rid].size = size;
      g_rtinfo->dfsan_records.buffer[rid].hval = hval;

      assert(pm_regions.regions[0].is_open == 1);
      g_rtinfo->dfsan_records.buffer[rid].offset = addr - pm_regions.regions[0].begin;

#ifdef STACK_TRACE_ENABLE
      fprintf(cb->trace_stream, "hash: dfsan-%lu\n", rid);
      fprintf(cb->trace_stream, "dfsan: %lu(W) 0x%016lx(addr)\n", hval, addr);
      printStackTrace(cb->trace_stream, 1);
#endif

      // char backup_img_dir[512];
      // // skip the suffix of "---cov"
      // snprintf(backup_img_dir, strlen(g_rtinfo->cov_path) - 5, "%s", g_rtinfo->cov_path);
      // char cmd[1024];
      // sprintf(cmd, "cp %s %s/pmem-dfsan-%lu.img", g_rtinfo->img_path, backup_img_dir, rid);
      // debug("cmd: %s\n", cmd);
      // system(cmd);
      DO_BACKUP_IMG("dfsan", rid)

      unflushed_cur->count--;
    }

    if (unflushed_cur->count == 0) {
      // remove the unflushed label from linked list
      if (unflushed_prev == NULL) {
        cb->unflushed_data_head = unflushed_cur->next;
      } else {
        unflushed_prev->next = unflushed_cur->next;
      }
      struct unflushed_data *unflushed_free = unflushed_cur;
      unflushed_cur = unflushed_cur->next;
      free(unflushed_free);
    } else {
      unflushed_prev = unflushed_cur;
      unflushed_cur = unflushed_cur->next;
    }
  }
  // if (unflushed_label) {
  //   dfsan_label store_label = dfsan_read_label((void*)addr,(size_t)size);
  //   if (dfsan_has_label(store_label, unflushed_label)) {
  //     debug("[thread-%d] write based on unflushed, 0x%016lx(addr), %lu(size), %lu(hval)\n",
  //       pid, addr, size, hval);
  //     unflushed_label = 0;
  //     // dfsan_label old_label = unflushed_label;
  //     // atomic_compare_exchange_strong()
  //   }
  // }

  /* init the cursors and hvals */
  ALIAS_CHECK_INIT(ar_cur, pr_cur)
  ALIAS_CHECK_INIT(aw_cur, pw_cur)
  MEMDU_CHECK_INIT(mr_cur, sr_cur)
  MEMDU_CHECK_INIT(mw_cur, sw_cur)

  for (i = 0; i < size; i++) {
    /* check PM alias instrunction pair (read-write) */
    mem_check_alias_reader(cb->pid, hval, addr + i, &s, &p, &p_pid);

    // check if we need to report XRW alias pair
    ALIAS_CHECK_LOOP(cb, hval, p_pid, addr, i, p, ar_cur, pr_cur, pr_pid, XRW_PAIR)

    // check if we need to report XRW memdu pair
    MEMDU_CHECK_LOOP(cb, hval, addr, i, s, mr_cur, sr_cur, XRW_PAIR)

    /* set the access info */
    cell.stat = is_non_temporal == 1 ? PM_CLEAN : PM_DIRTY;
    cell.pid = cb->pid;
    cell.inst = hval;

    /*
     * Check PM alias instrunction pair (write-write)
     * and take ownership of the cell.
     *
     * The checking and updating operations require a mutex for
     * corresponding memory cell. Hence, concurrent write-write
     * detection for the same address would always obtain an alias pair.
     */
    mem_check_alias_writer_for_writer(cb->pid, hval, addr + i, &s, &p, &cell, &p_pid);

    // check if we need to record XWW alias pair
    ALIAS_CHECK_LOOP(cb, hval, p_pid, addr, i, p, aw_cur, pw_cur, pw_pid, XWW_PAIR)

    // check if we need to report XWW memdu pair
    MEMDU_CHECK_LOOP(cb, hval, addr, i, s, mw_cur, sw_cur, XWW_PAIR)

    /* the ownership is handled in 'mem_check_alias_writer_for_writer' */
    // ht_hook_mc_get_slot(g_hook_mc_writer_ht, addr + i, __hook_mc_set_cell, &cell);
  }

  /* Flush alias/memdu pairs at the end of iteration */
  ALIAS_CHECK_FINI(cb, hval, addr, size, ar_cur, pr_cur, pr_pid, XRW_PAIR)
  ALIAS_CHECK_FINI(cb, hval, addr, size, aw_cur, pw_cur, pw_pid, XWW_PAIR)
  MEMDU_CHECK_FINI(cb, hval, addr, size, mr_cur, sr_cur, XRW_PAIR)
  MEMDU_CHECK_FINI(cb, hval, addr, size, mw_cur, sw_cur, XWW_PAIR)

#ifdef STACK_TRACE_ENABLE
  for (i = 0; i < g_rtinfo->sync.point_num; i++) {
    if (g_rtinfo->sync.pts[i].hval == hval &&
        g_rtinfo->sync.pts[i].type == CANDIDATE_RACE_WRITE) {
      printStackTrace(cb->writer_backtrace, 1);
      fseek(cb->writer_backtrace, 0, SEEK_SET);
      cb->last_sync_write_hval = hval;
    }
  }
#endif

  uint32_t in_sync = 0;
  for (i = 0; i < g_rtinfo->sync.point_num; i++) {
    if (g_rtinfo->sync.pts[i].hval == hval &&
        g_rtinfo->sync.pts[i].type == MEM_WRITE) {
      in_sync = 1;
      break;
    }
  }
  if (in_sync) {
    if (g_rtinfo->sync.pts[i].skip == 0) {
      debug("[thread-%u] writer broadcasts in 0x%016lx, %lu(hval)\n",
        pid, addr, hval);
      atomic_store(&g_rtinfo->sync.m, 1);

      // wait for readers
      usleep(1000);
    } else {
      debug("skip sync point [skip=%u]\n", g_rtinfo->sync.pts[i].skip);
      g_rtinfo->sync.pts[i].skip--;
    }
  }

}

// Cache flushes
void hook_cache_flush(uint64_t addr, hval_64_t hval) {
  HOOK_HANDLER_BEGIN()

  uint64_t flush_align = 64;
  assert((addr & (flush_align - 1)) == 0);

  FILTER_NON_PM_ACCESS(addr, flush_align)

  struct hook_mc cell;
  uint64_t i;
  uint64_t empty_cells = 0;

  // TODO: awareness of fences
  cell.stat = PM_CLEAN;

  pid_32_t pid = get_thread_id();
  debug("[thread-%u] clflush 0x%016lx, %lu(hval)\n", pid, addr, hval);

  for (i = 0; i < flush_align; i++) {
    // Use has_slot to clear PM state only when the cell exists
    void *r = ht_hook_mc_has_slot(
      // g_hook_mc_writer_ht,
      &g_rtinfo->hook_mc_writer_ht,
      addr + i,
      __hook_mc_set_cell_state,
      &cell
    );

    if (!r) {
      empty_cells++;
    }
  }

  if (empty_cells == flush_align) {
    // TODO:  1. report unnecessary flush without write
    //        2. report unnecessary flush for clean memory
    struct hook_cb *cb = hook_cb_get_or_create(pid);

#ifdef STACK_TRACE_ENABLE
    static __thread hval_64_t last_hval = 0;
    static __thread uint64_t last_addr = 0;

    // a simple filter to prune noises from range flushes
    if (last_hval != hval || last_addr + flush_align != addr) {
      // hist_hval = hval;
      cb->thread_trace_count++;
      debug("increase thread_trace_count to %lu trace_stream %p [pid-%u]\n",
            cb->thread_trace_count, cb->trace_stream, pid);
      fprintf(cb->trace_stream, "hash: %d-%lu\n", cb->pid,
              cb->thread_trace_count);
      fprintf(cb->trace_stream,
              "[PM performance bug] flush 0x%lx without writes\n", addr);
      printStackTrace(cb->trace_stream, 1);
    }
    last_hval = hval;
    last_addr = addr;
#else
    fprintf(stderr, "[PM performance bug] flush 0x%lx without writes\n", addr);
#endif
  }
}

// pmemobj_tx_begin (TX_BEGIN)
void hook_pmemobj_tx_begin(uint64_t hval, uint64_t pool_addr) {
  HOOK_HANDLER_BEGIN()

  debug("pool_addr: 0x%lx\n", pool_addr);

  pid_32_t pid = get_thread_id();
  struct hook_cb *cb = hook_cb_get_or_create(pid);

  if (cb->thread_tx_info.count != 0) {
    assert(cb->thread_tx_info.pool_addr == pool_addr &&
           "libpmemobj only allows nested tx for the same pool");
  } else {
    cb->thread_tx_info.pool_addr = pool_addr;
  }

  cb->thread_tx_info.count++;
}

// pmemobj_tx_add_common (TX_ADD)
void hook_pmemobj_tx_add_common(
  uint64_t hval, uint64_t tx_offset_addr, uint64_t tx_size_addr
) {
  HOOK_HANDLER_BEGIN()

  pid_32_t pid = get_thread_id();
  struct hook_cb *cb = hook_cb_get_or_create(pid);

  uint64_t tx_offset = *(uint64_t *)(tx_offset_addr);
  uint64_t tx_size = *(uint64_t *)(tx_size_addr);

  debug("hval: 0x%lx\n", hval);
  debug("tx offset: *(0x%lx) = %lu\n",
    tx_offset_addr, tx_offset);
  debug("tx size: *(0x%lx) = %lu\n",
    tx_size_addr, tx_size);

  struct tx_range *temp = malloc(sizeof(struct tx_range));

  assert(cb->thread_tx_info.count != 0 && "tx_add out of tx");

  // TODO: check if ranges are already added
  temp->begin = cb->thread_tx_info.pool_addr + tx_offset;
  temp->end = temp->begin + tx_size;
  temp->next = cb->tx_range_head;
  cb->tx_range_head = temp;

  debug("add tx_range: [0x%lx, 0x%lx] pool = 0x%lx\n", temp->begin, temp->end,
        cb->thread_tx_info.pool_addr);
}

// pmemobj_tx_end (TX_END)
void hook_pmemobj_tx_end(uint64_t hval) {
  HOOK_HANDLER_BEGIN()

  pid_32_t pid = get_thread_id();
  struct hook_cb *cb = hook_cb_get_or_create(pid);

  assert(cb->thread_tx_info.count != 0 && "tx_end without of tx_begin");
  debug("call pmemobj_tx_end\n");

  cb->thread_tx_info.count--;

  // Since "pmemobj_tx_commit" commits in the outest tx, we clear
  // tx_ranges in a similar way.
  // TODO: confirm the behavior of nested txs
  if (cb->thread_tx_info.count == 0) {
    // encounter the outest tx, clear tx_ranges and tx_info
    struct tx_range *tx_range_it = cb->tx_range_head, *temp;
    while (tx_range_it != NULL) {
      temp = tx_range_it->next;
      free(tx_range_it);
      tx_range_it = temp;
    }

    cb->tx_range_head = NULL;
    cb->thread_tx_info.pool_addr = 0;

    debug("free tx_ranges\n");
  }
}

// foo
void hook_foo(uint64_t pool_addr, uint64_t b_addr) {
  HOOK_HANDLER_BEGIN()

  debug("pool_addr: 0x%lx\n", pool_addr);
  debug("b_addr: 0x%lx, b: %d\n", b_addr, *(int *)(b_addr));
}

// obj_runtime_init
void hook_obj_runtime_init(
  uint64_t pool_addr, uint64_t heap_offset_addr, uint64_t heap_size_addr
) {
  HOOK_HANDLER_BEGIN()

  uint64_t heap_offset = *(uint64_t *)(heap_offset_addr);
  uint64_t heap_size = *(uint64_t *)(heap_size_addr);

  debug("pool_addr: 0x%lx\n", pool_addr);
  debug("heap offset: *(0x%lx) = %lu\n",
    heap_offset_addr, heap_offset);
  debug("heap size: *(0x%lx) = %lu\n",
    heap_size_addr, heap_size);

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
}

// pmem_map_fileU
void hook_pmem_map_fileU(uint64_t pool_addr, uint64_t size_addr) {
  HOOK_HANDLER_BEGIN()

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
}

// open
void hook_open(const char *path, uint32_t fd) {
  HOOK_HANDLER_BEGIN()

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
  HOOK_HANDLER_BEGIN()

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
}

// Branch coverage
void hook_branch_enter(hval_64_t hval) {
  HOOK_HANDLER_BEGIN()

  pid_32_t pid = get_thread_id();
  struct hook_cb *cb = hook_cb_get_or_create(pid);

  cov_cfg_add_edge(hash_u64_into_h24_chain(cb->last_blk, hval));
  cb->last_blk = hval;
}

// Synchronization variable's annotation
void hook_annotation(hval_64_t hval, uint64_t var_addr, uint64_t size, uint64_t val) {
  HOOK_HANDLER_BEGIN()

  FILTER_NON_PM_ACCESS(var_addr, size)

  // TODO:: remove hval
  // debug("sync var annotation: hval = 0x%lx, addr = 0x%lx, size = %lu, val = %lu\n",
  //   hval, var_addr, size, val);

  // hack: assume that there is only one PM pool (the first mmapped pool)
  uint64_t offset = var_addr - pm_regions.regions[0].begin;
  annotation_add_sync_hint(var_addr, var_addr, offset, size, val);

}
