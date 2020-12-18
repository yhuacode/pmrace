from typing import List, Tuple, Dict

import shutil
import os
import glob
import json
import logging
import random
import time
import pprint

import config
import workload_config

from queue import Empty
from collections import namedtuple
from multiprocessing import Process, Queue

from workload_config import Program
from trace_walker import TraceRecord, TraceWalker
from fuzz_exec import FeedBack, FuzzExec, DFSanRecord
from fuzz_validate import FuzzValidate, FuzzValidateSyncVar
from json_helper import JsonHelper
from util import multiplex_logging, execute0

Seed = namedtuple('Seed', ['id', 'path'])
InconsistentWrite = namedtuple(
    'InconsistentWrite',
    ['dfsan_record', 'record_path']
)
SyncVar = namedtuple(
    'SyncVar',
    ['record_path', 'img_path']
)

Record = namedtuple(
    'Record', config.RECORD_COLUMNS
)

def get_identifier_from_dfsan_path(p: str):
    return p.rsplit('/', 1)[1].split('---')[0]

def get_identifier_from_sync_var_path(p: str):
    return p.rsplit('/', 2)[1]

class ValidateWorker(object):

    def __init__(
        self, meta_info: Dict, pmdk_info: Dict, code: Dict,
        worker_id: int, sync_queue: Queue, dfsan_queue: Queue
    ) -> None:
        self.meta_info = meta_info
        self.pmdk_info = pmdk_info
        self.code = code
        self.worker_id = worker_id

        self.sync_queue = sync_queue
        self.dfsan_queue = dfsan_queue

        self.output_dir = None
        self.maps_dir = None

        self.dfsan_id = None
        self.dfsan_record = None

        self.sync_id = None

        self.save_debug_log = config.SAVE_DEBUG_LOG

    def _prepare_sync_var_input(self, sync_var: SyncVar) -> None:
        identifier = get_identifier_from_sync_var_path(sync_var.img_path)

        self.output_dir = config.VALIDATE_OUTPUT_ROOT + '/' + identifier
        self.maps_dir = self.output_dir + '/' + 'maps'
        assert os.path.exists(self.maps_dir)

        self.sync_id = sync_var.img_path.rsplit('/', 1)[1].split('.')[0]

        # copy the pm image
        img_path = sync_var.img_path
        assert os.path.exists(img_path), img_path + ' not exists'

        self.pool_path = config.VALIDATE_IMG_PATH.format(
            self.output_dir, self.sync_id
        )
        shutil.copyfile(
            img_path,
            self.pool_path
        )

        self.sync_record_path = sync_var.record_path

    def _prepare_iwrite_input(self, iwrite: InconsistentWrite) -> None:
        identifier = get_identifier_from_dfsan_path(iwrite.record_path)

        self.output_dir = config.VALIDATE_OUTPUT_ROOT + '/' + identifier
        self.maps_dir = self.output_dir + '/' + 'maps'
        assert os.path.exists(self.maps_dir)

        self.dfsan_id = iwrite.dfsan_record.id
        self.dfsan_record = iwrite.dfsan_record

        # copy the pm image
        temp = iwrite.record_path.split('---')
        assert len(temp) == 2, str(temp)

        image_folder = temp[0]
        img_path = config.VALIDATE_IMG_PATH.format(
            image_folder, self.dfsan_id
        )
        assert os.path.exists(img_path), img_path + ' not exists'

        self.pool_path = config.VALIDATE_IMG_PATH.format(
            self.output_dir, self.dfsan_id
        )
        shutil.copyfile(
            img_path,
            self.pool_path
        )

        # save inconsistent record in a input file
        self.inconsistent_write_path = config.VALIDATE_INCONSISTENT_WRITE_PATH.format(
            self.output_dir, self.dfsan_id
        )
        with open(self.inconsistent_write_path, 'w') as f:
            f.write('{} {}'.format(iwrite.dfsan_record.offset, iwrite.dfsan_record.size))

    def _execute_cmd(
        self, runner, cmd: List[str], **kwargs
    ) -> None:
        runner.run(cmd, **kwargs)

    def _execute_validate_sync_var(self, cmd: List[str]) -> None:
        output_dir = self.output_dir
        sync_id = self.sync_id
        logging.info('validating ' + sync_id)

        status_path = output_dir + '/' + sync_id + '---stat'
        error_path = output_dir + '/' + sync_id + '---program_error.log'
        stack_trace_path = output_dir + '/' + sync_id + '---stacktrace'
        parsed_bug_path = stack_trace_path + '.true.err'
        parsed_fp_path = stack_trace_path + '.false.err'

        runner = FuzzValidateSyncVar(
            worker_id=self.worker_id,
            code=self.code,
            status_path=status_path,
            pool_path=self.pool_path,
            maps_dir=self.maps_dir,
            sync_var_path=self.sync_record_path,
            output_dir=output_dir,
            error_path=error_path,
            stack_trace_path=stack_trace_path,
            parsed_bug_path=parsed_bug_path,
            parsed_fp_path=parsed_fp_path
        )

        log_path = output_dir + '/' + sync_id + '.log'
        logging.info('[worker-{}] cmd: {}, pool: {}, log: {}'.format(
            self.worker_id,
            cmd,
            self.pool_path,
            log_path
        ))

        with open(os.devnull, 'r') as f_seed:
            if self.save_debug_log:
                logging.info('outputs will be saved in ' + log_path)
                with multiplex_logging(log_path):
                    self._execute_cmd(runner, cmd, stdin=f_seed)
            else:
                self._execute_cmd(runner, cmd, stdin=f_seed)

    def _execute_validate_dfsan(self, cmd: List[str]) -> None:
        output_dir = self.output_dir
        dfsan_id = self.dfsan_id
        logging.info('validating ' + dfsan_id)

        status_path = output_dir + '/' + dfsan_id + '---stat'
        error_path = output_dir + '/' + dfsan_id + '---program_error.log'
        stack_trace_path = output_dir + '/' + dfsan_id + '---stacktrace'
        parsed_bug_path = stack_trace_path + '.true.err'
        parsed_fp_path = stack_trace_path + '.false.err'

        runner = FuzzValidate(
            worker_id=self.worker_id,
            code=self.code,
            dfsan_record=self.dfsan_record,
            status_path=status_path,
            pool_path=self.pool_path,
            maps_dir=self.maps_dir,
            inconsistent_write_path=self.inconsistent_write_path,
            output_dir=output_dir,
            error_path=error_path,
            stack_trace_path=stack_trace_path,
            parsed_bug_path=parsed_bug_path,
            parsed_fp_path=parsed_fp_path
        )

        log_path = output_dir + '/' + dfsan_id + '.log'
        logging.info('[worker-{}] cmd: {}, pool: {}, log: {}'.format(
            self.worker_id,
            cmd,
            self.pool_path,
            log_path
        ))

        with open(os.devnull, 'r') as f_seed:
            if self.save_debug_log:
                logging.info('outputs will be saved in ' + log_path)
                with multiplex_logging(log_path):
                    self._execute_cmd(runner, cmd, stdin=f_seed)
            else:
                self._execute_cmd(runner, cmd, stdin=f_seed)

    def launch(self, program: Program) -> None:
        logging.info('[worker-{}] starts'.format(self.worker_id))

        sync_var = self.sync_queue.get()
        while sync_var is not None:
            self._prepare_sync_var_input(sync_var)
            cmd = program.gen_cmd(self.worker_id, self.pool_path)
            self._execute_validate_sync_var(cmd)
            sync_var = self.sync_queue.get()

        iwrite = self.dfsan_queue.get()
        while iwrite is not None:
            self._prepare_iwrite_input(iwrite)
            cmd = program.gen_cmd(self.worker_id, self.pool_path)
            self._execute_validate_dfsan(cmd)
            iwrite = self.dfsan_queue.get()

        logging.info('[worker-{}] finishes'.format(self.worker_id))


class FuzzWorker(object):

    def __init__(
        self, meta_info: Dict, pmdk_info: Dict, code: Dict,
        mem_access: List, worker_id: int, seed_queue: Queue, mode: str
    ) -> None:
        self.meta_info = meta_info
        self.pmdk_info = pmdk_info
        self.code = code
        self.mem_access = mem_access
        self.worker_id = worker_id

        self.seed_queue = seed_queue
        # self.result_queue = result_queue
        self.exploration_mode = mode

        self.seed_id = 0
        self.seed_path = ""

        self.interleaving_id = 0
        self.total_runs = 0

        self.output_dir = None
        self.maps_dir = None

        self.ttl_run_loop = config.TTL_RUN_LOOP
        self.ttl_interleaving_loop = config.TTL_INTERLEAVING_LOOP
        self.ttl_seed_loop = config.TTL_SEED_LOOP

        self.from_empty_pool = config.FROM_EMPTY_POOL
        self.save_debug_log = config.SAVE_DEBUG_LOG

        self.record_handler = open(
            config.COV_INCR_RECORD_WORKER_PATH.format(worker_id), 'w'
        )

        self.skipped_insts = {}

        # clear after each run
        self.disabled_insts = set()

        # clear for a new seed
        self.walker = TraceWalker(self.meta_info, self.pmdk_info)
        self.writer_insts = set()
        self.testing_write_inst = None
        self.alias_pair_map = {}
        self.memdu_pair_map = {}

        self.messages_for_logging = {
            'delay_info': "",
            'debugging': ""
        }

    def _prepare_seed(self, seed: Seed) -> None:
        self.seed_id = seed.id
        self.seed_path = seed.path
        self.interleaving_id = 0

        self.output_dir = config.OUTPUT_DIR.format(seed.id)
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)

        self.maps_dir = config.MAPS_DIR.format(seed.id)
        if not os.path.exists(self.maps_dir):
            os.mkdir(self.maps_dir)

    def _random_inject_delay(self) -> None:
        assert len(self.mem_access) > 0

        delay_config_path = config.DELAY_PATH.format(self.seed_id)
        logging.debug('inject delay as "{}"'.format(delay_config_path))
        with open(delay_config_path, 'w') as f:
            for inst in self.mem_access:
                f.write('{} {}\n'.format(
                    inst, random.randint(0, config.DELAY_MAX_US)
                ))

            # backup delay.txt
            shutil.copyfile(
                delay_config_path,
                config.DELAY_BACKUP_PATH.format(
                    self.seed_id, self.seed_id, self.interleaving_id
                )
            )

        self.interleaving_id += 1

    def _pmrace_inject_delay(self, feedback: FeedBack) -> None:
        if self.testing_write_inst:
            self.writer_insts.add(self.testing_write_inst)

        for inst in self.disabled_insts:
            if inst not in self.skipped_insts:
                self.skipped_insts[inst] = 1
            else:
                self.skipped_insts[inst] += 1
        self.disabled_insts.clear()

        self.interleaving_id += 1
        assert not self.walker.is_empty()
        points = self.walker.get_injection_points()
        assert points

        sync_insts = []
        for point in points:
            for x in point['writers']:
                if x[0] not in self.writer_insts:
                    sync_insts.append({
                        'hval': x[0],
                        'type': 'w',
                        'info': x,
                        'priority': point['priority'],
                        'skip': 0
                    })
                    self.testing_write_inst = x[0]
                    break

            # skip points without new writers
            if not sync_insts:
                continue

            for x in point['readers']:
                skip = 0
                if x[0] in self.skipped_insts:
                    skip = self.skipped_insts[x[0]]
                sync_insts.append({
                    'hval': x[0],
                    'type': 'r',
                    'info': x,
                    'priority': point['priority'],
                    'skip': skip
                })

            if len(sync_insts) == 1:
                # skip points without readers
                sync_insts.clear()
            else:
                for x in point['writers']:
                    sync_insts.append({
                        'hval': x[0],
                        'type': 'c',
                        'info': x,
                        'priority': point['priority'],
                        'skip': skip
                    })
                break

        logging.info('{} sync insts'.format(
            len(sync_insts)
        ))

        self.messages_for_logging['delay_info'] = (
            str(self.total_runs) +
            '> shared memory addresses info from walker: \n' +
            pprint.pformat(points) + '\n' + '*' * 80 +
            '\ndetailed sync points info: \n' +
            pprint.pformat(sync_insts)
        )

        sync_config_path = config.SYNC_PATH.format(
            self.seed_id, self.seed_id, self.interleaving_id
        )
        logging.info('apply sync info as "{}"'.format(sync_config_path))

        with open(sync_config_path, 'w') as f:
            f.write('{} {}\n'.format(
                len(sync_insts), workload_config.P_CLHT_THREAD_NUM
            ))
            for inst in sync_insts:
                f.write('{} {} {}\n'.format(
                    inst['hval'], inst['type'], inst['skip']
                ))


    def _execute_cmd(
        self, runner: FuzzExec, cmd: List[str], **kwargs
    ) -> FeedBack:
        logging.debug(self.messages_for_logging['debugging'])
        logging.debug(self.messages_for_logging['delay_info'])
        return runner.run(cmd, **kwargs)

    def _execute(self, cmd: List[str]) -> Tuple:
        seed_id = self.seed_id
        seed_path = self.seed_path
        interleaving_id = self.interleaving_id
        runs = self.total_runs

        logging.info(
            'fuzz executing seed {} interleaving {} total runs {}'
            .format(seed_id, interleaving_id, runs)
        )

        status_path = config.STATUS_PATH.format(seed_id)
        pool_path = config.PMEM_POOL_PATH_PREFIX + str(self.worker_id)
        race_path = config.RACE_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        unflushed_path = config.UNFLUSHED_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        dfsan_path = config.DFSAN_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        cov_path = config.COV_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        stack_trace_path = config.STACKTRACE_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        inconsistent_write_path = config.INCONSISTENT_WRITE_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        backup_img_path = config.BACKUP_IMG_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        skipped_inst_path = config.SKIPPED_INST_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        sync_config_path = config.SYNC_PATH.format(
            seed_id, seed_id, interleaving_id
        )

        error_path = config.OUTPUT_ERROR_PATH.format(seed_id)
        parsed_race_path = config.PARSED_RACE_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        parsed_unflushed_path = config.PARSED_UNFLUSHED_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )
        curr_path_suffix = config.CURR_CSV_SUFFIX
        parsed_sync_path = config.PARSED_SYNC_PATH.format(
            seed_id, seed_id, interleaving_id, runs
        )

        runner = FuzzExec(
            worker_id=self.worker_id,
            code=self.code,
            status_path=status_path,
            pool_path=pool_path,
            race_path=race_path,
            unflushed_path=unflushed_path,
            dfsan_path=dfsan_path,
            cov_path=cov_path,
            sync_config_path=sync_config_path,
            maps_dir=self.maps_dir,
            output_dir=self.output_dir,
            error_path=error_path,
            parsed_race_path=parsed_race_path,
            parsed_unflushed_path=parsed_unflushed_path,
            curr_path_suffix=curr_path_suffix,
            skipped_inst_path=skipped_inst_path,
            stack_trace_path=stack_trace_path,
            inconsistent_write_path=inconsistent_write_path,
            backup_img_path=backup_img_path,
            parsed_sync_path=parsed_sync_path
        )

        # pre-execution: clear pool if necessary
        if self.from_empty_pool:
            if os.path.isfile(pool_path):
                os.remove(pool_path)

        logging.info('[worker-{}] cmd: {}, seed: {}, delay: {}'.format(
            self.worker_id,
            cmd,
            seed_path,
            config.DELAY_BACKUP_PATH.format(seed_id, seed_id, interleaving_id)
        ))

        with open(seed_path, 'r') as f_seed:
            if self.save_debug_log:
                log_path = config.PMRACE_LOG_PATH.format(
                    seed_id, seed_id, interleaving_id, runs
                )
                logging.info('outputs will be saved in ' + log_path)
                with multiplex_logging(log_path):
                    feedback = self._execute_cmd(runner, cmd, stdin=f_seed)
            else:
                feedback = self._execute_cmd(runner, cmd, stdin=f_seed)

        logging.info('[worker-{}] obtain feedback\n'
            '\tcov_cfg_incr: {}, cov_dfg_incr: {}, cov_alias_incr: {}'.format(
                self.worker_id,
                feedback.cov_cfg_edge_incr,
                feedback.cov_dfg_edge_incr,
                feedback.cov_alias_inst_incr
            )
        )

        record = Record(
            int(time.time()), 'worker-' + str(self.worker_id),
            seed_id, interleaving_id, runs,
            feedback.cov_cfg_edge_incr,
            feedback.cov_dfg_edge_incr,
            feedback.cov_alias_inst_incr
        )
        self.record_handler.write(','.join([str(x) for x in record]) + '\n')

        # flush records to disk
        self.record_handler.flush()
        os.fsync(self.record_handler.fileno())

        for inst in feedback.skipped_insts:
            self.disabled_insts.add(inst)

        self.total_runs += 1

        # update walker
        if self.walker.is_empty():
            for x in feedback.curr_memdu:
                if x.hash not in self.memdu_pair_map:
                    self.memdu_pair_map[x.hash] = x
            for x in feedback.curr_alias:
                if x.hash not in self.alias_pair_map:
                    self.alias_pair_map[x.hash] = x
            self.walker.group_records(
                feedback.curr_memdu, feedback.curr_alias
            )
        else:
            new_memdu = []
            for x in feedback.curr_memdu:
                if x.hash not in self.memdu_pair_map:
                    self.memdu_pair_map[x.hash] = x
                    new_memdu.append(x)
            new_alias = []
            for x in feedback.curr_alias:
                if x.hash not in self.alias_pair_map:
                    self.alias_pair_map[x.hash] = x
                    new_alias.append(x)

            if new_memdu or new_alias:
                self.walker.update_records(
                    new_memdu, new_alias
                )

        # check if this seed increases any coverage
        if (feedback.cov_cfg_edge_incr != 0 or
            feedback.cov_dfg_edge_incr != 0 or
            feedback.cov_alias_inst_incr != 0):
            return True, feedback

        # nothing interesting found
        return False, feedback

    def _interleaving_inner_loop(self, cmd: List[str], enable_analysis: bool) -> Tuple:
        stall = 0

        # assert config.RUN_FOR_ANALYSIS <= self.ttl_run_loop

        while True:
            useful, feedback = self._execute(cmd)
            if useful:
            # if enable_analysis and self.num_analysis < config.RUN_FOR_ANALYSIS:
                if self.interleaving_id == 0:
                    points = self.walker.get_injection_points()
                    self.messages_for_logging['debugging'] = (
                        str(self.total_runs) +
                        '> updated shared memory addresses: \n' +
                        pprint.pformat(points) + '\n' + '*' * 80 + '\n'
                    )

                return True, feedback

            stall += 1
            if stall == self.ttl_run_loop:
                return False, feedback

    def _case_inner_loop(self, cmd: List[str]) -> bool:
        stall = 0

        while True:
            useful, feedback = self._interleaving_inner_loop(cmd, True)
            if useful:
                return True

            stall += 1
            if stall == self.ttl_interleaving_loop:
                return False

            if self.exploration_mode == 'pmrace':
                self._pmrace_inject_delay(feedback) # proactive thread scheduling
            elif self.exploration_mode == 'random':
                self._random_inject_delay() # random delay injection
            # self.num_analysis = 0

    def _fuzz_inner_loop(self, cmd: List[str]) -> bool:
        stall = 0

        while True:
            useful = self._case_inner_loop(cmd)
            if useful:
                return True

            stall += 1
            if stall == self.ttl_seed_loop:
                return False

    def launch(self, program: Program) -> None:
        logging.info('[worker-{}] starts'.format(self.worker_id))

        cmd = program.gen_cmd(self.worker_id)

        seed = self.seed_queue.get()
        while seed is not None:
            self._prepare_seed(seed)

            while self._fuzz_inner_loop(cmd):
                pass

            seed = self.seed_queue.get()

            self.walker.clear()
            self.writer_insts.clear()
            self.testing_write_inst = None
            self.alias_pair_map = {}
            self.memdu_pair_map = {}

        logging.info('[worker-{}] finishes'.format(self.worker_id))
        self.record_handler.close()


class FuzzProbe(object):

    def __init__(
        self, seed_dir: str, meta_path: str, meta_dir: str, pmdk_path: str,
        obj_json_path: str, pmdk_json_path: str, exploration_mode: str
    ) -> None:
        # input files
        self.seed_dir = seed_dir
        self.meta_path = meta_path
        self.meta_dir = meta_dir
        self.pmdk_path = pmdk_path

        self.obj_json_path = obj_json_path
        self.pmdk_json_path = pmdk_json_path

        self.output_root = None
        self.worker_num = config.WORKER_NUM

        self.meta_info = None
        self.pmdk_info = None
        self.code = None

        # used in fuzzing stage
        self.mem_access = []
        self.seed_queue = Queue()
        self.record_paths = []

        self.exploration_mode = exploration_mode

        # used in validating stage
        self.dfsan_queue = Queue()
        self.sync_queue = Queue()

    def _setup_fuzzing(self) -> None:
        self.output_root = config.OUTPUT_ROOT

        if not os.path.exists(self.output_root):
            os.mkdir(self.output_root)

        self._parse_meta()

        seeds = sorted(glob.glob(self.seed_dir + '/id*'))
        for i in range(len(seeds)):
            self.seed_queue.put(Seed(id=i, path=seeds[i]))

        logging.debug('found {} seeds in {}'
            .format(self.seed_queue.qsize(), self.seed_dir))

        if self.worker_num > len(seeds):
            logging.warning('worker_num({}) > # of seed({}), '
                'set worker_num to {}'.format(
                self.worker_num, len(seeds), len(seeds)
            ))
            self.worker_num = len(seeds)

        # put an ending mark for each worker
        for i in range(self.worker_num):
            self.seed_queue.put(None)
            self.record_paths.append(
                config.COV_INCR_RECORD_WORKER_PATH.format(i)
            )

    def _set_sync_vars(self) -> None:
        sync_var_files = []
        seed_folders = sorted(glob.glob(config.OUTPUT_ROOT + '/seed*'))
        for folder in seed_folders:
            # find stack traces of synchronization inconsistencies
            sync_stack_traces = glob.glob(folder + '/*sync.parsed')
            for p in sync_stack_traces:
                sync_record_folder = p.rsplit('---', 1)[0]
                sync_var_files += glob.glob(sync_record_folder + '/sync-*.txt')
        logging.debug('sync_var_files: ' + str(sync_var_files))

        for s_f in sync_var_files:
            folder, filename = s_f.rsplit('/', 1)
            pm_img_path =  config.VALIDATE_IMG_PATH.format(folder, filename.split('.', 1)[0])

            # create the folders (e.g., seed{}-inter{}-run{} and maps) for validation
            identifier = get_identifier_from_sync_var_path(pm_img_path)
            validate_dir = self.output_root + '/' + identifier
            if not os.path.exists(validate_dir):
                os.mkdir(validate_dir)

            maps_dir = validate_dir + '/' + 'maps'
            if not os.path.exists(maps_dir):
                os.mkdir(maps_dir)

            self.sync_queue.put(
                SyncVar(s_f, pm_img_path)
            )

        queue_size = self.sync_queue.qsize()
        logging.info('found {} sync vars'.format(queue_size))

    def _set_dfsan_records(self) -> None:
        err_files = []
        seed_folders = sorted(glob.glob(config.OUTPUT_ROOT + '/seed*'))
        for folder in seed_folders:
            # find inter- and intra- thread inconsistencies
            err_files += glob.glob(folder + '/*.parsed.err')
        err_files = sorted(err_files)

        bug_IDs = []
        for e_f in err_files:
            with open(e_f, 'r') as f:
                contents = f.read().strip().split('\n\n')

                for content in contents:
                    content = content.strip()

                    # skip possible empty contents
                    if not content:
                        continue

                    reader_pos = content.rfind('hash: ')
                    assert reader_pos != -1

                    # obtain the ID from log, e.g., the "xxx" in "hash: xxx" is ID
                    bug_IDs.append(content[reader_pos:].split('\n', 1)[0].split(' ', 1)[1])

            dfsan_file_path = e_f.split('---')[0] + '---dfsan.csv'

            # create the folders (e.g., seed{}-inter{}-run{} and maps) for validation
            identifier = get_identifier_from_dfsan_path(dfsan_file_path)
            validate_dir = self.output_root + '/' + identifier
            if not os.path.exists(validate_dir):
                os.mkdir(validate_dir)

            maps_dir = validate_dir + '/' + 'maps'
            if not os.path.exists(maps_dir):
                os.mkdir(maps_dir)

            records = []
            with open(dfsan_file_path, 'r') as f:
                lines = f.read().strip().split('\n')[1:]
                records = [DFSanRecord(*line.strip().split(',')) for line in lines]
            logging.debug('found {} dfsan records from {}'.format(
                len(records), dfsan_file_path
            ))
            logging.debug('bug_IDs: {}'.format(bug_IDs))

            for r in records:
                if r.hash in bug_IDs:
                    self.dfsan_queue.put(
                        InconsistentWrite(r, dfsan_file_path)
                    )

        queue_size = self.dfsan_queue.qsize()
        logging.info('enqueue {} dfsan records'.format(queue_size))

    def _setup_validating(self) -> None:
        self.output_root = config.VALIDATE_OUTPUT_ROOT
        self.worker_num = 1 # single-thread validation is enough

        if not os.path.exists(self.output_root):
            os.mkdir(self.output_root)

        self._parse_meta()

        self._set_sync_vars()

        self._set_dfsan_records()

        total_records = self.dfsan_queue.qsize() + self.sync_queue.qsize()
        if self.worker_num > total_records:
            logging.warning('worker_num({}) > # of records({}), '
                'set worker_num to {}'.format(
                self.worker_num, total_records, total_records
            ))
            self.worker_num = total_records

        # put an ending mark for each worker
        for i in range(self.worker_num):
            self.sync_queue.put(None)
            self.dfsan_queue.put(None)

    def _parse_meta(self) -> None:
        jh = JsonHelper()

        if self.obj_json_path:
            # load obj json file
            with open(self.obj_json_path, 'r') as f:
                meta_info = json.load(f)
        else:
            # generate obj json file
            meta_info = {'functions': {}, 'instructions': {}}
            if os.path.exists(self.meta_path):
                jh.parse_meta_json(self.meta_path, meta_info)

            whole_json = 'obj.json'
            if os.path.exists(whole_json):
                os.remove(whole_json)

            if self.meta_dir:
                jh.parse_meta_dir_json(self.meta_dir, meta_info)

            with open(whole_json, 'w') as f:
                json.dump(meta_info, f, indent=2)

        self.meta_info = meta_info
        self.code = meta_info

        for inst_hval, inst in self.code['instructions'].items():
            if 'repr' not in inst:
                continue

            inst_repr = inst['repr']
            if ('load' in inst_repr or
                'store' in inst_repr or
                'memcpy' in inst_repr or
                'memset' in inst_repr or
                'memmove' in inst_repr):
                self.mem_access.append(inst['hash'])

        if self.pmdk_json_path:
            # load pmdk json file
            pmdk_json = self.pmdk_json_path
        else:
            # generate pmdk json file
            pmdk_json = os.path.join(self.pmdk_path, "pmdk.json")
            if not os.path.exists(pmdk_json):
                jh.concat_json_files(self.pmdk_path, pmdk_json)

        self.pmdk_info = jh.update_json(pmdk_json, self.code)

    def _save_records(self) -> None:
        outs, _ = execute0(['cat'] + self.record_paths)

        title_line = config.COV_INCR_RECORD_TEMPLATE.format(
            *config.RECORD_COLUMNS
        )
        with open(config.COV_INCR_RECORD_PATH, 'w') as f:
            f.write(title_line + '\n' + outs)

        cfg_cov = 0
        dfg_cov = 0
        alias_cov = 0
        records = []

        lines = outs.strip().split('\n')
        for line in lines:
            r = Record(*[x for x in line.split(',')])

            cfg_cov += int(r.cfg_cov_incr)
            dfg_cov += int(r.dfg_cov_incr)
            alias_cov += int(r.alias_cov_incr)
            records.append((r.tid, line))

        logging.info(
            '\t total: runs = {}, cfg_cov = {}, dfg_cov = {}, alias_cov = {}'
            .format(
                len(lines), cfg_cov, dfg_cov, alias_cov
            )
        )
        with open(config.COV_INCR_RECORD_SORTED_PATH, 'w') as f:
            f.write(title_line + '\n')

            for t in sorted(records, key=lambda x: x[0]):
                f.write(t[1] + '\n')

            f.write(',,,,{},{},{},{}'.format(
                len(lines), cfg_cov, dfg_cov, alias_cov
            ))

    def _launch_fuzzing(self, program: Program) -> None:
        self._setup_fuzzing()

        processes = [
            Process(
                target=fuzzing_process,
                args=(
                    program, self.meta_info, self.pmdk_info, self.code,
                    self.mem_access, i, self.seed_queue, self.exploration_mode
                )
            )
            for i in range(self.worker_num)
        ]

        for p in processes:
            p.start()

        for p in processes:
            p.join()

        self._save_records()
        logging.info('Fuzzing completes.')

    def _launch_validating(self, program: Program) -> None:
        self._setup_validating()

        processes = [
            Process(
                target=validating_process,
                args=(
                    program, self.meta_info, self.pmdk_info, self.code,
                    i, self.sync_queue, self.dfsan_queue
                )
            )
            for i in range(self.worker_num)
        ]

        for p in processes:
            p.start()

        for p in processes:
            p.join()

        logging.info('Validating completes.')

    def launch(self, program: Program, fuzzing: bool) -> None:
        if fuzzing:
            self._launch_fuzzing(program)
        else:
            self._launch_validating(program)


def fuzzing_process(
    program: Program, meta_info: Dict, pmdk_info: Dict, code: Dict,
    mem_access: List, worker_id: int, seed_queue: Queue, mode: str
):
    worker = FuzzWorker(
        meta_info, pmdk_info, code, mem_access, worker_id, seed_queue, mode
    )
    worker.launch(program)


def validating_process(
    program: Program, meta_info: Dict, pmdk_info: Dict, code: Dict,
    worker_id: int, sync_queue: Queue, dfsan_queue: Queue
):
    worker = ValidateWorker(
        meta_info, pmdk_info, code, worker_id, sync_queue, dfsan_queue
    )
    worker.launch(program)
