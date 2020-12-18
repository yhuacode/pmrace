#include "hook_ctrl.h"

// A flag indicating the completion of hook_main_enter.
atomic_int main_entered = 0;

uint32_t g_instance_id = 0;

// dfsan_label unflushed_label = 0;

// // Reader/Writer set of memory cells (at runtime)
// //
// // Used for the detection of cross-thread inconsistency at runtime
// // only. We need to create and initialize the table for each test.
// ht_hook_mc_t *g_hook_mc_reader_ht = NULL;
// ht_hook_mc_t *g_hook_mc_writer_ht = NULL;

// // Crontrol block info (at runtime)
// ht_hook_cb_t *g_hook_cb_ht = NULL;


// Branch coverage and alias coverage (in shared memory)
//
// Used as progress for coverage-guided fuzz testing. Hence, the
// two coverage metrics should be globally visible during the whole
// fuzzing. We can store the coverage in shared memory.
struct hook_shminfo *g_shminfo = NULL;
// unsigned long *g_cov_cfg_edge = NULL;
// unsigned long *g_cov_alias_inst = NULL;

// const char *pm_state_str[] = {
//   "FLUSHED",
//   "UNFLUSHED",
//   "UNDETERMINED"
// };

const char *pair_type_str[] = {
  "XRR",
  "XRW",  // 1
  "",
  "XWW",  // 3
  "", "", "", "", "", "",
  "UWR",  // 10
  "", "", "",
  "PWR"   // 14
};


// Runtime info (in output files)
//
// The runtime information is generated in a fuzz campaign
// (i.e., one execution) and used to provide hints for later
// actions, e.g., injecting different delays in current seed
// or changing seeds. To make the data available to fuzzers,
// we can save the runtime info in shared memory in output files.
struct hook_rtinfo *g_rtinfo = NULL;

// struct hook_pair_records *g_new_races = NULL;

// struct hook_pair_records *g_new_memdu = NULL;

// _Atomic(struct hook_stack_trace_node *) g_stack_traces = NULL;


/* PM regions */
const char *pm_pool_path_pattern = "pmem";
uint32_t pm_pool_cand_fds[PM_POOL_CAND_MAX];

struct pm_regions_info pm_regions;

int init_shared_coverage_info() {
  int r = attach_shared_coverage_info();

  if (r != -1) {
    memset(g_shminfo, 0, sizeof(struct hook_shminfo));
  }

  return r;
}

int free_shared_coverage_info() {
  int shmid = attach_shared_coverage_info();
  if (shmid == -1) {
    return -1;
  }

  if (shmctl(shmid, IPC_RMID, 0) == -1) {
    perror("shmctl");
    return -1;
  }

  return 0;
}
