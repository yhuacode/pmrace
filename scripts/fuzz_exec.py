from typing import List, Tuple, Dict

import shutil
import os
import logging
import json
import sys
import random
import pprint
import glob

import config

from collections import namedtuple

from util import execute0, enable_coloring_in_logging, ProgramError
from whitelist import WHITELIST_LOCS
from trace_walker import TraceRecord, TraceWalker

DFSanRecord = namedtuple(
    'DFSanRecord', ['id', 'pid', 'flags', 'hash', 'addr', 'size', 'offset', 'hval']
)


class FeedBack(object):

    def __init__(
        self, cfg_edge: int, dfg_edge: int, alias_inst: int,
        cfg_edge_incr: int, dfg_edge_incr: int, alias_inst_incr: int,
        curr_memdu: List[TraceRecord], curr_alias: List[TraceRecord],
        memdu_records: List[TraceRecord], alias_records: List[TraceRecord],
        skipped_insts: List
    ) -> None:
        self.cov_cfg_edge = cfg_edge
        self.cov_dfg_edge = dfg_edge
        self.cov_alias_inst = alias_inst
        self.cov_cfg_edge_incr = cfg_edge_incr
        self.cov_dfg_edge_incr = dfg_edge_incr
        self.cov_alias_inst_incr = alias_inst_incr
        self.curr_memdu = curr_memdu
        self.curr_alias = curr_alias
        self.memdu_records = memdu_records
        self.alias_records = alias_records
        self.skipped_insts = skipped_insts


class AddrTransformer(object):

    stack_trace_token = 'stack trace: pid'
    stack_trace_delimiter = '-'*60
    instrumented_libs = [
        'libPMRaceHook.so',
        'libpmem.so.1.0.0',
        'libpmemobj.so.1.0.0',
        'libpmemkv.so.1',
    ]
    addr2line_path = config.ADDR2LINE_BIN_PATH
    cxxfilt_path = config.CXXFILT_BIN_PATH

    def __init__(
        self, binary: str, src: str, maps_dir: str
    ) -> None:
        self.binary_name = binary.strip().rsplit('/', 1)[-1]
        self.instrumented_bins = [*self.instrumented_libs, self.binary_name]

        self.src = src
        self.maps_dir = maps_dir
        self.maps_cache = {}
        self.loc_cache = {}

    def _addr2line(self, exe: str, addr: str) -> str:
        key = exe + '-' + addr
        if key in self.loc_cache:
            return self.loc_cache[key]

        outs, errs = execute0([self.addr2line_path, '-e', exe, addr, '-fpCi'])
        outs = outs[:-1]
        outs1, errs = execute0([self.cxxfilt_path, outs.split(" ")[0]])
        outs1 = outs1[:-1] + " " + outs.split(" ", 1)[1]
        loc = outs1.strip()

        # cache results from addr2line
        self.loc_cache[key] = loc

        return loc

    def _extract_start_addr(self, map_path: str) -> Dict:
        # search cached results
        if map_path in self.maps_cache:
            logging.debug('found libs in cache: {}'.format(
                str(self.maps_cache[map_path])))
            return self.maps_cache[map_path]

        lib_dict = {}
        with open(map_path) as f:
            for line in f.read().strip().split('\n'):
                line = line.strip()

                # filter unrelated libs
                tds = line.rsplit('/', 1)
                if len(tds) == 1 or tds[1] not in self.instrumented_bins:
                    continue

                # filter mapped regions without 'r-xp' permissions
                info = line.split(' ', 2)
                assert len(info) == 3
                if info[1] != 'r-xp':
                    continue

                assert tds[1] not in lib_dict
                saddr, _ = info[0].split('-')
                lib_dict[tds[1]] = int('0x' + saddr, base=16)

        logging.debug('candidate libs: {}'.format(self.instrumented_bins))
        logging.debug('extract {} libs: {}'.format(len(lib_dict), str(lib_dict)))

        # cache results
        self.maps_cache[map_path] = lib_dict

        return lib_dict

    def transform(self) -> Dict:
        lines = self.src.strip().split('\n')
        logging.debug('AddrTransformer: inputs {} lines'.format(len(lines)))

        trace_map = {}
        i = 0
        while i < len(lines):
            line = lines[i]

            tds = line.split('=', 1)
            if tds[0].strip() != self.stack_trace_token:
                i += 1
                continue

            pid = tds[1].strip()
            map_path = os.path.join(self.maps_dir, 'maps_' + pid)
            lib_dict = self._extract_start_addr(map_path)

            # trace begin
            i += 1
            assert lines[i] == self.stack_trace_delimiter
            r_lines = lines[i-3:i+1]
            hval = lines[i-3].strip().split(' ')[1]

            # process trace until end
            i += 1
            while lines[i] != self.stack_trace_delimiter:
                loc_tuple = lines[i].strip().split(' ')

                assert len(loc_tuple) == 4, 'error loc_tuple: {}\nline: {}\nhval: {}'.format(
                    loc_tuple, lines[i], hval
                )

                _, addr, _, exe = lines[i].strip().split(' ')

                # minus lib start addr
                exe_info = exe.rsplit('/', 1)
                if len(exe_info) ==2 and exe_info[1] in self.instrumented_bins:
                    addr = hex(int(addr, base=16) - lib_dict[exe_info[1]])

                if addr[0] == '-':
                    logging.error('A negative address: {}\npid: {}\nline: {}'
                        .format(addr, pid, lines[i]))

                r_lines.append('{}\n\t\t[{}]'.format(
                    lines[i], self._addr2line(exe, addr)
                ))
                i += 1
            r_lines.append(lines[i])

            if hval in trace_map:
                # FIXME
                logging.error(
                    'error trace_map: hval={}\nold={}\nnew={}'.format(
                        hval, trace_map[hval], '\n'.join(r_lines)
                    )
                )
                assert False and "hval in trace_map"

            # assert hval not in trace_map
            trace_map[hval] = '\n'.join(r_lines)

        return trace_map

class FuzzExec(object):

    def __init__(
        self, worker_id: int, code: Dict, status_path: str, pool_path: str,
        race_path: str, unflushed_path: str, dfsan_path: str,
        cov_path: str, sync_config_path: str,
        maps_dir: str, output_dir: str, error_path: str,
        parsed_race_path: str, parsed_unflushed_path: str,
        curr_path_suffix: str, skipped_inst_path: str,
        stack_trace_path: str, inconsistent_write_path: str,
        backup_img_path: str, parsed_sync_path: str
    ) -> None:
        self.worker_id = worker_id
        self.code = code

        # input/output path
        self.status_path = status_path

        # inputs path
        self.pool_path = pool_path
        self.race_path = race_path
        self.unflushed_path = unflushed_path
        self.dfsan_path = dfsan_path
        self.cov_path = cov_path
        self.sync_config_path = sync_config_path
        self.maps_dir = maps_dir

        # outputs path
        self.output_dir = output_dir
        self.error_path = error_path
        self.parsed_race_path = parsed_race_path
        self.parsed_unflushed_path = parsed_unflushed_path
        self.curr_path_suffix = curr_path_suffix
        self.skipped_inst_path = skipped_inst_path
        self.stack_trace_path = stack_trace_path
        self.inconsistent_write_path = inconsistent_write_path
        self.backup_img_path = backup_img_path
        self.parsed_sync_path = parsed_sync_path

        self.trace_map = None
        self.dfsan_map = {}

    def _extrace_traces(self, binary: str) -> None:
        with open(self.stack_trace_path, 'r') as f:
            outs = f.read()
        self.trace_map = AddrTransformer(binary, outs, self.maps_dir).transform()

    def _process_xxx_csv(self, path: str, debug_tag: str, FormatCls) -> List:
        with open(path, 'r') as f:
            lines = f.read().strip().split('\n')[1:]
            records = [FormatCls(*line.strip().split(',')) for line in lines]

            for r in records:
                logging.debug('{}: {}'.format(debug_tag, r))

            return records

    def _process_race_csv(self) -> List[TraceRecord]:
        return self._process_xxx_csv(self.race_path, 'race record', TraceRecord)

    def _process_unflushed_csv(self) -> List[TraceRecord]:
        return self._process_xxx_csv(self.unflushed_path, 'unflushed record', TraceRecord)

    def _process_dfsan_csv(self) -> List[DFSanRecord]:
        if os.path.exists(self.dfsan_path):
            return self._process_xxx_csv(self.dfsan_path, 'dfsan record', DFSanRecord)
        else:
            return []

    def _process_sync_var(self) -> List[str]:
        sync_var_folder = self.race_path.split('---')[0]
        logging.debug('sync_var_folder: {} (from {})'.format(sync_var_folder, self.race_path))
        if os.path.exists(sync_var_folder):
            sync_vars = sorted(glob.glob(sync_var_folder + '/sync-*.txt'))
            # obtain the filenames w/o suffix
            results = [x.rsplit('/', 1)[1].split('.', 1)[0] for x in sync_vars]
            return results
        else:
            return []

    def _process_skipped_insts(self) -> List:
        with open(self.skipped_inst_path, 'r') as f:
            lines = f.read().strip().split('\n')

            skipped_insts = []
            for inst in lines:
                if inst:
                    skipped_insts.append(int(inst))
                    logging.debug('found skipped inst, hval: {}'.format(inst))

            return skipped_insts

    def _analyze_record(self, record: TraceRecord) -> Tuple[str, str]:
        logging.debug(str(record))

        # assert record.src_raw in self.code['instructions']
        if record.src_raw not in self.code['instructions']:
            logging.error('record.src_raw {} error'.format(record.src_raw))
            logging.error('all insts: {}'.format(self.code['instructions'].keys()))

        # assert record.dst_raw in self.code['instructions']
        if record.dst_raw not in self.code['instructions']:
            logging.error('record.dst_raw {} error'.format(record.dst_raw))
            logging.error('all insts: {}'.format(self.code['instructions'].keys()))

        line = ''
        has_dependent_write = False
        if record.tag == 'UWR' and record.hash in self.dfsan_map:
            for r in self.dfsan_map[record.hash]:
                pm_write = self.code['instructions'][r.hval]

                # detect PM writes to the same address
                if int(r.addr, base=16) == record.addr:
                    logging.debug(
                        '_analyze_record: write to unflushed data, not bugs'
                        '{}(pid) {}(addr) {}(size) {}(hval)\n\t{} {}'.format(
                            r.pid, r.addr, r.size, r.hval,
                            pm_write['repr'], pm_write['info']
                        )
                    )
                    continue

                has_dependent_write = True
                line += 'DFSAN: [thread-{}] pm write {}(pid) {}(addr) {}(size) {}(flags)\n\t{} {}\n'.format(
                    r.pid, r.addr, r.size, r.hval, r.flags,
                    pm_write['repr'], pm_write['info']
                )
                if r.id in self.trace_map:
                    line = line + self.trace_map[r.id] + '\n'
                else:
                    logging.warning('not found trace record for ' + r.id)

        from_item = self.code['instructions'][record.src_raw]
        to_item = self.code['instructions'][record.dst_raw]
        line += '{} {} {}(size) {}(prev_hval) {}(prev_pid) {}(curr_hval) {}(curr_pid)\n\t{} {}\n\t{} {}'.format(
            record.tag, hex(record.addr), record.size, record.src, record.pid1, record.dst, record.pid2,
            from_item['repr'], from_item['info'],
            to_item['repr'], to_item['info'],
        )

        return line, record.tag, record.hash, record.dst, has_dependent_write

    def _is_in_white_list(self, report: str) -> bool:
        for loc in WHITELIST_LOCS:
            if loc in report:
                return True

        return False

    def _save_race_pairs(self, pairs: List[TraceRecord]) -> None:
        lines = []
        errors = []
        for pair in pairs:
            line, race_type, hval, r_hval, has_error = self._analyze_record(pair)

            # we focus on inter-thread inconsistency
            if race_type != 'UWR':
                continue

            w_trace_id = hval + '-writer'
            if w_trace_id in self.trace_map:
                w_trace = self.trace_map[w_trace_id]
            else:
                w_trace = 'Missing corresponding store stack trace'

            if hval not in self.trace_map:
                print('xxx: {} not in {}'.format(hval, str(self.trace_map.keys())))
            r_trace = self.trace_map[hval]

            if self._is_in_white_list(r_trace):
                logging.debug('Found one race in the white list\n'
                    + line + '\n' + r_trace)
                continue

            lines.append(line)
            lines.append(w_trace)
            lines.append(r_trace)
            lines.append('\n\n')

            if has_error:
                errors.append(line)
                errors.append(w_trace)
                errors.append(r_trace)
                errors.append('\n\n')

                # print inter-thread inconsistency
                logging.error('[worker-{}] '.format(self.worker_id)
                    + 'Found one inter-thread inconsistency race'
                    ' (saved in {})\n'.format(self.parsed_race_path)
                    + line + '\n' + r_trace)
            else:
                logging.warning('[worker-{}] '.format(self.worker_id)
                    + 'Found one inter-thread reading unflushed (maybe benign) '
                    + line)

        if lines:
            with open(self.parsed_race_path, 'w') as f:
                f.write('\n'.join(lines))

        # save errors
        if errors:
            with open(self.parsed_race_path + '.err', 'w') as f:
                f.write('\n'.join(errors))

    def _save_unflushed_cases(self, cases: List[TraceRecord]) -> None:
        lines = []
        errors = []
        for case in cases:
            line, tag, hval, r_hval, has_error = self._analyze_record(case)

            # we focus on reading unflushed
            if tag != 'UWR':
                continue

            w_trace_id = hval + '-writer'
            if w_trace_id in self.trace_map:
                w_trace = self.trace_map[w_trace_id]
            else:
                w_trace = 'Missing corresponding store stack trace'

            if hval not in self.trace_map:
                print('xxx: {} not in {}'.format(hval, str(self.trace_map.keys())))
            r_trace = self.trace_map[hval]

            if self._is_in_white_list(r_trace):
                logging.debug('Found one unflushed in the white list\n'
                    + line + '\n' + r_trace)
                continue

            lines.append(line)
            lines.append(w_trace)
            lines.append(r_trace)
            lines.append('\n\n')

            if has_error:
                errors.append(line)
                errors.append(w_trace)
                errors.append(r_trace)
                errors.append('\n\n')

                # print sequential inconsistency
                logging.error('[worker-{}] '.format(self.worker_id)
                    + 'Found one inconsistency for sequential execution'
                    ' (saved in {})\n'.format(self.parsed_unflushed_path)
                    + line + '\n' + r_trace)
            else:
                logging.warning('[worker-{}] '.format(self.worker_id)
                    + 'Found one sequential reading unflushed (maybe benign) '
                    + line)
        if lines:
            with open(self.parsed_unflushed_path, 'w') as f:
                f.write('\n'.join(lines))

        # save errors
        if errors:
            with open(self.parsed_unflushed_path + '.err', 'w') as f:
                f.write('\n'.join(errors))

    def _save_sync_var_records(self, cases: List[str]):
        lines = []
        for case in cases:
            if case not in self.trace_map:
                print('xxx: {} not in {}'.format(case, str(self.trace_map.keys())))
            r_trace = self.trace_map[case]

            if self._is_in_white_list(r_trace):
                logging.debug('Found one sync var in the white list\n' + r_trace)
                continue

            lines.append(r_trace)
            lines.append('\n\n')

            logging.error('[worker-{}] '.format(self.worker_id)
                + 'Found one modification about sync var (maybe benign): '
                + case + '\n'
                + r_trace)

        if lines:
            with open(self.parsed_sync_path, 'w') as f:
                f.write('\n'.join(lines))


    def _group_dfsan_records(self, records: List[DFSanRecord]) -> None:
        for r in records:
            if r.hash not in self.dfsan_map:
                self.dfsan_map[r.hash] = [r]
            else:
                self.dfsan_map[r.hash].append(r)

        # # save inconsistent writes and corresponding PM image
        # if result:
        #     logging.debug('save inconsistent writes in '
        #         + self.inconsistent_write_path)
        #     with open(self.inconsistent_write_path, 'w') as f:
        #         for r in result:
        #             f.write('{} {}\n'.format(r[0], r[1]))

        #     # backup pm image
        #     logging.debug('backup pm image in '
        #         + self.backup_img_path)
        #     shutil.copyfile(
        #         self.pool_path, self.backup_img_path
        #     )

    def run(self, cmd: List[str], **kwargs) -> FeedBack:
        # set environment variables
        envs = {
            **os.environ,
            'PMEM_POOL': self.pool_path,
            'PMRACE_SYNC_CONFIG_PATH': self.sync_config_path,
            'OUTPUT_DIR': self.output_dir,
            'PMRACE_RACE_PATH': self.race_path,
            'PMRACE_UNFLUSHED_PATH': self.unflushed_path,
            'PMRACE_DFSAN_PATH': self.dfsan_path,
            'PMRACE_COV_PATH': self.cov_path,
            'PMRACE_SKIP_PATH': self.skipped_inst_path,
            'PMRACE_STACKTRACE_PATH': self.stack_trace_path,
            'PMRACE_INSTANCE_ID': str(self.worker_id),
            'ENABLE_TRACE_ANALYSIS': '1',
            'DFSAN_OPTIONS': 'warn_unimplemented=0'
        }

        try:
            with open(self.status_path, 'w') as f:
                # To indicate the program is running
                f.write('1')

            outs, errs = execute0(cmd, env=envs, **kwargs)
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
                # failed to execute hook_main_exit
                env_str = ('Runtime environment variables are as follows:\n'
                    'PMEM_POOL={}\n'
                    'OUTPUT_DIR={}\n'
                    'PMRACE_SYNC_CONFIG_PATH={}\n'
                    'PMRACE_RACE_PATH={}\n'
                    'PMRACE_UNFLUSHED_PATH={}\n'
                    'PMRACE_DFSAN_PATH={}\n'
                    'PMRACE_COV_PATH={}\n'
                    'PMRACE_SKIP_PATH={}\n'
                    'PMRACE_STACKTRACE_PATH={}\n'
                    'PMRACE_INSTANCE_ID={}\n'
                    'ENABLE_TRACE_ANALYSIS={}\n'
                    'DFSAN_OPTIONS=warn_unimplemented=0'.format(
                        self.pool_path, self.output_dir,
                        self.sync_config_path, self.race_path,
                        self.unflushed_path, self.dfsan_path,
                        self.cov_path, self.skipped_inst_path,
                        self.stack_trace_path, self.worker_id, 1
                    )
                )

                logging.error('fail to run cmd: {}\n{}'.format(cmd, env_str))
                with open(self.error_path, 'w') as f:
                    f.write('Summary: {}\n{}\n'.format(e.message, env_str))
                    f.write('------- stdout --------\n' + e.outs + '\n')
                    f.write('------- stderr --------\n' + e.errs + '\n')
                raise e
        except RuntimeError as e:
            raise e

        logging.debug('stdout:{}\n{}\n{}'.format('#'*80, outs, '#'*80))
        logging.debug('stderr:{}\n{}\n{}'.format('#'*80, errs, '#'*80))

        return self.process(cmd, outs, errs)

    def process(self, cmd: List[str], outs: str, errs: str) -> FeedBack:
        # translate addr to lines
        self._extrace_traces(cmd[0])

        # record pm writes based on reading unflushed
        dfsan_records = self._process_dfsan_csv()

        # parse dfsan records
        self._group_dfsan_records(dfsan_records)

        # process race pairs (csv records)
        alias_records = self._process_race_csv()
        curr_alias_pairs = self._process_xxx_csv(
            self.race_path + self.curr_path_suffix,
            'current race pairs',
            TraceRecord
        )

        # parse race pairs and save results
        self._save_race_pairs(alias_records)

        # process unflushed records (csv records)
        memdu_records = self._process_unflushed_csv()
        curr_memdu_pairs = self._process_xxx_csv(
            self.unflushed_path + self.curr_path_suffix,
            'current memdu pairs',
            TraceRecord
        )

        # parse memdu pairs and save results
        self._save_unflushed_cases(memdu_records)

        # process sync vars (text records)
        sync_var_tag = self._process_sync_var()
        print('sync vars: ' + pprint.pformat(sync_var_tag))

        # parse sync vars and save results
        self._save_sync_var_records(sync_var_tag)

        # parse skipped insts during execution
        skipped_insts = self._process_skipped_insts()

        with open(self.cov_path, 'r') as f:
            lines = f.readlines()
            curr_cov = [int(x) for x in lines[0].strip().split(',')]
            cov_incr = [int(x) for x in lines[1].strip().split(',')]

            return FeedBack(
                *curr_cov, *cov_incr,
                curr_memdu_pairs, curr_alias_pairs,
                memdu_records, alias_records, skipped_insts
            )


if __name__ == '__main__':
    enable_coloring_in_logging()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )

    binary_name = sys.argv[1]
    outs = open(sys.argv[2]).read()
    at = AddrTransformer(binary_name, outs, sys.argv[3])
    maps = at.transform()
    for k, v in maps.items():
        logging.error('{} --> {}'.format(k, v))
