import os

WORKER_NUM = 4

DELAY_MAX_US = 1000

VALIDATION_TIMEOUT_S = 300

SAVE_DEBUG_LOG = True

ADDR2LINE_BIN_PATH = '/usr/bin/addr2line'
CXXFILT_BIN_PATH = '/home/vagrant/llvm-11/bin/llvm-cxxfilt'
CLEANUP_BIN_PATH = os.path.join(os.environ['PMRACE_DIR'], 'scripts/clear_states_only.sh')

OUTPUT_ROOT = 'output'
OUTPUT_DIR = OUTPUT_ROOT + '/seed{}'
OUTPUT_ERROR_PATH = OUTPUT_DIR + '/program_error.log'

VALIDATE_OUTPUT_ROOT = 'validate'
VALIDATE_IMG_PATH = '{}/pmem-{}.img'
VALIDATE_INCONSISTENT_WRITE_PATH = '{}/iwrite-{}'

RACE_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---race.csv'
UNFLUSHED_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---unflushed.csv'
DFSAN_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---dfsan.csv'
COV_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---cov'
SKIPPED_INST_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---skipped'
STACKTRACE_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---stacktrace'
INCONSISTENT_WRITE_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---write'
BACKUP_IMG_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---img'

PARSED_RACE_PATH = RACE_PATH + '.parsed'
PARSED_UNFLUSHED_PATH = UNFLUSHED_PATH + '.parsed'
PARSED_SYNC_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}---sync.parsed'

STATUS_PATH = OUTPUT_DIR + '/stat'
DELAY_PATH = OUTPUT_DIR + '/delay.txt'
DELAY_BACKUP_PATH = OUTPUT_DIR + '/seed{}-inter{}---delay.txt'

SYNC_PATH = OUTPUT_DIR + '/seed{}-inter{}---sync.txt'

PMRACE_LOG_PATH = OUTPUT_DIR + '/seed{}-inter{}-run{}.log'

MAPS_DIR = OUTPUT_DIR + '/maps'

TTL_RUN_LOOP = 3
TTL_INTERLEAVING_LOOP = 6
TTL_SEED_LOOP = 1

CURR_CSV_SUFFIX = '.curr.csv'

FROM_EMPTY_POOL = True
# PMEM_POOL_PATH_PREFIX = '/mnt/pmem0/pmrace/pmem_pool_'  # use PM
PMEM_POOL_PATH_PREFIX = 'pmem_pool_'  # use disk

RECORD_COLUMNS = [
    'tid', 'worker_id', 'seed_id', 'inter_id', 'runs',
    'cfg_cov_incr', 'dfg_cov_incr', 'alias_cov_incr'
]

COV_INCR_RECORD_TEMPLATE = '{},{},{},{},{},{},{},{}'
COV_INCR_RECORD_WORKER_PATTERN = os.path.join(OUTPUT_ROOT, 'cov_incr-worker-*.csv')
COV_INCR_RECORD_WORKER_PATH = os.path.join(OUTPUT_ROOT, 'cov_incr-worker-{}.csv')

COV_INCR_RECORD_PATH = os.path.join(OUTPUT_ROOT, 'cov_incr.csv')
COV_INCR_RECORD_SORTED_PATH = os.path.join(OUTPUT_ROOT, 'cov_incr_sorted.csv')

INJECTION_POINT_LIMIT = 100
RUN_FOR_ANALYSIS = 3
