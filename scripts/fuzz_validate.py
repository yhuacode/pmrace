from typing import List, Tuple, Dict

import shutil
import os
import logging
import json
import sys
import random
import pprint

import config

from fuzz_exec import AddrTransformer, DFSanRecord
from util import execute, execute0, enable_coloring_in_logging, ProgramError
from whitelist import WHITELIST_LOCS


class FuzzValidate(object):

    def __init__(
        self, worker_id: int, code: Dict, dfsan_record: DFSanRecord,
        status_path: str, pool_path: str,
        maps_dir: str, inconsistent_write_path: str, output_dir: str,
        error_path: str, stack_trace_path: str, parsed_bug_path: str,
        parsed_fp_path: str
    ) -> None:
        self.worker_id = worker_id
        self.code = code
        self.dfsan_record = dfsan_record

        # input/output path
        self.status_path = status_path

        # inputs path
        self.pool_path = pool_path
        self.maps_dir = maps_dir
        self.inconsistent_write_path = inconsistent_write_path

        # outputs path
        self.output_dir = output_dir
        self.error_path = error_path
        self.stack_trace_path = stack_trace_path
        self.parsed_bug_path = parsed_bug_path
        self.parsed_fp_path = parsed_fp_path

        self.trace_map = None

    def _extrace_traces(self, binary: str) -> None:
        with open(self.stack_trace_path, 'r') as f:
            outs = f.read()

        if len(outs.strip()) != 0:
            self.trace_map = AddrTransformer(binary, outs, self.maps_dir).transform()
        else:
            logging.debug('deleting empty stacktrace file: ' + self.stack_trace_path)
            os.remove(self.stack_trace_path)

    def run(self, cmd: List[str], **kwargs) -> None:
        # set environment variables
        envs = {
            **os.environ,
            'PMEM_POOL': self.pool_path,
            'PMRACE_INCONSISTENT_PATH': self.inconsistent_write_path,
            'PMRACE_SYNC_VAR_PATH': '',
            'OUTPUT_DIR': self.output_dir,
            'PMRACE_STACKTRACE_PATH': self.stack_trace_path,
            'PMRACE_STATUS_PATH': self.status_path,
            'PMRACE_INSTANCE_ID': str(self.worker_id),
            'DFSAN_OPTIONS': 'warn_unimplemented=0'
        }
        has_program_error = False

        try:
            with open(self.status_path, 'w') as f:
                # To indicate the program is running
                f.write('1')

            outs, errs = execute0(
                cmd, timeout=config.VALIDATION_TIMEOUT_S, timeout_allowed=True,
                env=envs, **kwargs
            )
        except ProgramError as e:
            f_stat = open(self.status_path, 'r')
            p_stat = int(f_stat.read().strip())
            f_stat.close()

            if p_stat == 0:
                # hook_main_exit succeeded
                outs = e.outs
                errs = e.errs
                logging.warning('[worker-{}] abnormal exit. CMD: {}'.format(
                    self.worker_id, cmd
                ))
            else:
                # failed to execute hook_main_exit, which indicates that
                # the recovery logic of PM program is buggy
                has_program_error = True

                env_str = ('Runtime environment variables are as follows:\n'
                    'PMEM_POOL={}\n'
                    'PMRACE_INCONSISTENT_PATH={}\n'
                    'PMRACE_SYNC_VAR_PATH=""\n'
                    'OUTPUT_DIR={}\n'
                    'PMRACE_STACKTRACE_PATH={}\n'
                    'PMRACE_STATUS_PATH={}\n'
                    'PMRACE_INSTANCE_ID={}\n'
                    'DFSAN_OPTIONS=warn_unimplemented=0'.format(
                        self.pool_path, self.inconsistent_write_path,
                        self.output_dir, self.stack_trace_path,
                        self.status_path, self.worker_id
                    )
                )

                logging.error('[worker-{}] fail to run cmd: {}. Reason: {}\n{}'.format(
                    self.worker_id, cmd, e.message, env_str
                ))
                with open(self.error_path, 'w') as f:
                    f.write('Summary: {}\n{}\n'.format(e.message, env_str))
                    f.write('------- stdout --------\n' + e.outs + '\n')
                    f.write('------- stderr --------\n' + e.errs + '\n')

                # clean up
                logging.info('clean the states for failure')
                execute([config.CLEANUP_BIN_PATH])

        except RuntimeError as e:
            raise e

        if not has_program_error:
            logging.debug('stdout:{}\n{}\n{}'.format('#'*80, outs, '#'*80))
            logging.debug('stderr:{}\n{}\n{}'.format('#'*80, errs, '#'*80))
            self.process(cmd, outs, errs)

    def _is_in_white_list(self, report: str) -> bool:
        for loc in WHITELIST_LOCS:
            if loc in report:
                return True

        return False

    def _analyze_report(self, tag: str, trace: str) -> str:
        lines = trace.strip().split('\n')
        assert len(lines) >= 5, str(lines)

        hval = lines[1].split(':', 1)[1].split('(', 1)[0].strip()
        assert hval in self.code['instructions'], '{}(hval) {}(type)'.format(hval, type(hval))
        access = self.code['instructions'][hval]

        prev_hval = self.dfsan_record.hval
        if prev_hval in self.code['instructions']:
            # we are running validation under the same env with fuzzing stage
            prev_write = self.code['instructions'][prev_hval]

            line = ('{} {} {} {}(prev_write)\n\tPre-failure write: {} {}'
                    '\n\tPost-failure access: {} {}'.format(
                tag, self.dfsan_record.id, self.dfsan_record.hash, self.dfsan_record.hval,
                prev_write['repr'], prev_write['info'],
                access['repr'], access['info']
            ))
        else:
            line = ('{} {} {} {}(prev_write)\n\tPost-failure access: {} {}'.format(
                tag, self.dfsan_record.id, self.dfsan_record.hash, self.dfsan_record.hval,
                access['repr'], access['info']
            ))

        return line

    def _process_reports(self) -> None:
        if not self.trace_map:
            return

        f_bug = open(self.parsed_bug_path, 'w')
        f_fp = open(self.parsed_fp_path, 'w')
        for k, v in self.trace_map.items():
            if k[0] == 'T':
                if self._is_in_white_list(v):
                    logging.debug('Found one race in the white list\n' + v)
                    continue

                line = self._analyze_report(k, v)
                f_bug.write(line + '\n' + v + '\n')
                logging.error('[worker-{}] '.format(self.worker_id)
                    + 'Found reading inconsistent'
                    ' (saved in {})\n'.format(self.parsed_bug_path)
                    + line + '\n' + v)

            elif k[0] == 'F':
                line = self._analyze_report(k, v)
                f_fp.write(line + '\n' + v + '\n')
                logging.warning('[worker-{}] '.format(self.worker_id)
                    + 'Found overwritten inconsistent'
                    ' (saved in {})\n'.format(self.parsed_fp_path))
            else:
                raise RuntimeError('Unknow trace ID ' + k)

        # remove empty reports
        if f_bug.tell() == 0:
            f_bug.close()
            os.remove(self.parsed_bug_path)
        else:
            f_bug.close()

        if f_fp.tell() == 0:
            f_fp.close()
            os.remove(self.parsed_fp_path)
        else:
            f_fp.close()

    def process(self, cmd: List[str], outs: str, errs: str) -> None:
        # translate addr to lines
        self._extrace_traces(cmd[0])

        # process and save traces
        self._process_reports()


class FuzzValidateSyncVar(object):

    def __init__(
        self, worker_id: int, code: Dict,
        status_path: str, pool_path: str,
        maps_dir: str, sync_var_path: str, output_dir: str,
        error_path: str, stack_trace_path: str, parsed_bug_path: str,
        parsed_fp_path: str
    ) -> None:
        self.worker_id = worker_id
        self.code = code

        # input/output path
        self.status_path = status_path

        # inputs path
        self.pool_path = pool_path
        self.maps_dir = maps_dir
        self.sync_var_path = sync_var_path

        # outputs path
        self.output_dir = output_dir
        self.error_path = error_path
        self.stack_trace_path = stack_trace_path
        self.parsed_bug_path = parsed_bug_path
        self.parsed_fp_path = parsed_fp_path

        self.trace_map = None

    def _extrace_traces(self, binary: str) -> None:
        with open(self.stack_trace_path, 'r') as f:
            outs = f.read()

        if len(outs.strip()) != 0:
            self.trace_map = AddrTransformer(binary, outs, self.maps_dir).transform()
        else:
            logging.debug('deleting empty stacktrace file: ' + self.stack_trace_path)
            os.remove(self.stack_trace_path)

    def run(self, cmd: List[str], **kwargs) -> None:
        # set environment variables
        envs = {
            **os.environ,
            'PMEM_POOL': self.pool_path,
            'PMRACE_INCONSISTENT_PATH': '',
            'PMRACE_SYNC_VAR_PATH': self.sync_var_path,
            'OUTPUT_DIR': self.output_dir,
            'PMRACE_STACKTRACE_PATH': self.stack_trace_path,
            'PMRACE_STATUS_PATH': self.status_path,
            'PMRACE_INSTANCE_ID': str(self.worker_id),
            'DFSAN_OPTIONS': 'warn_unimplemented=0'
        }
        has_program_error = False

        try:
            with open(self.status_path, 'w') as f:
                # To indicate the program is running
                f.write('1')

            outs, errs = execute0(
                cmd, timeout=config.VALIDATION_TIMEOUT_S, timeout_allowed=True,
                env=envs, **kwargs
            )
        except ProgramError as e:
            f_stat = open(self.status_path, 'r')
            p_stat = int(f_stat.read().strip())
            f_stat.close()

            if p_stat == 0:
                # hook_main_exit succeeded
                outs = e.outs
                errs = e.errs
                logging.warning('[worker-{}] abnormal exit. CMD: {}'.format(
                    self.worker_id, cmd
                ))
            else:
                # failed to execute hook_main_exit, which indicates that
                # the recovery logic of PM program is buggy
                has_program_error = True

                env_str = ('Runtime environment variables are as follows:\n'
                    'PMEM_POOL={}\n'
                    'PMRACE_INCONSISTENT_PATH=""\n'
                    'PMRACE_SYNC_VAR_PATH={}\n'
                    'OUTPUT_DIR={}\n'
                    'PMRACE_STACKTRACE_PATH={}\n'
                    'PMRACE_STATUS_PATH={}\n'
                    'PMRACE_INSTANCE_ID={}\n'
                    'DFSAN_OPTIONS=warn_unimplemented=0'.format(
                        self.pool_path, self.sync_var_path,
                        self.output_dir, self.stack_trace_path,
                        self.status_path, self.worker_id
                    )
                )

                logging.error('[worker-{}] fail to run cmd: {}. Reason: {}\n{}'.format(
                    self.worker_id, cmd, e.message, env_str
                ))
                with open(self.error_path, 'w') as f:
                    f.write('Summary: {}\n{}\n'.format(e.message, env_str))
                    f.write('------- stdout --------\n' + e.outs + '\n')
                    f.write('------- stderr --------\n' + e.errs + '\n')

                # clean up
                logging.info('clean the states for failure')
                execute([config.CLEANUP_BIN_PATH])
        except RuntimeError as e:
            raise e

        if not has_program_error:
            logging.debug('stdout:{}\n{}\n{}'.format('#'*80, outs, '#'*80))
            logging.debug('stderr:{}\n{}\n{}'.format('#'*80, errs, '#'*80))
            self.process(cmd, outs, errs)

    def _analyze_report(self, tag: str, trace: str) -> str:
        lines = trace.strip().split('\n')
        assert len(lines) >= 5, str(lines)

        hval = lines[1].split(':', 1)[1].split('(', 1)[0].strip()
        assert hval in self.code['instructions'], '{}(hval) {}(type)'.format(hval, type(hval))
        access = self.code['instructions'][hval]

        line = ('{}\n\tPost-failure access: {} {}'.format(
            tag, access['repr'], access['info']
        ))

        return line

    def _process_reports(self) -> None:
        if not self.trace_map:
            return

        f_bug = open(self.parsed_bug_path, 'w')
        f_fp = open(self.parsed_fp_path, 'w')
        for k, v in self.trace_map.items():
            if k[0] == 'T':
                line = self._analyze_report(k, v)
                f_bug.write(line + '\n' + v + '\n')
                logging.error('[worker-{}] '.format(self.worker_id)
                    + 'Found acquiring unreleased sync var'
                    ' (saved in {})\n'.format(self.parsed_bug_path)
                    + line + '\n' + v)

            elif k[0] == 'F':
                line = self._analyze_report(k, v)
                f_fp.write(line + '\n' + v + '\n')
                logging.warning('[worker-{}] '.format(self.worker_id)
                    + 'Found initializing unreleased sync var'
                    ' (saved in {})\n'.format(self.parsed_fp_path))
            else:
                raise RuntimeError('Unknow trace ID ' + k)

        # remove empty reports
        if f_bug.tell() == 0:
            f_bug.close()
            os.remove(self.parsed_bug_path)
        else:
            f_bug.close()

        if f_fp.tell() == 0:
            f_fp.close()
            os.remove(self.parsed_fp_path)
        else:
            f_fp.close()

    def process(self, cmd: List[str], outs: str, errs: str) -> None:
        # translate addr to lines
        self._extrace_traces(cmd[0])

        # process and save traces
        self._process_reports()


if __name__ == '__main__':
    enable_coloring_in_logging()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )
