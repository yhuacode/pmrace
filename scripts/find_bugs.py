from typing import List, Tuple, Dict

import shutil
import os
import glob
import logging
import pprint
import sys
import re
import shutil
import argparse

import buglist

from util import enable_coloring_in_logging
from whitelist import WHITELIST_LOCS

INTERTHREAD_INCONSISTENCY_FILE_PATTERN = '*race.csv.parsed.err'
INTRATHREAD_INCONSISTENCY_FILE_PATTERN = '*unflushed.csv.parsed.err'
SYNC_INCONSISTENCY_FILE_PATTERN = '*sync.parsed'

INTERTHREAD_INCONSISTENCY_CANDIDATE_FILE_PATTERN = '*race.csv.parsed'

def is_in_white_list(content: str):
    trace_begin = content.find('UWR')
    assert trace_begin != -1

    for line in WHITELIST_LOCS:
        found = content.find(line, trace_begin)
        if found != -1:
            return True

    return False

def find_errs(output_dir: str, pattern: str, is_sync_var=False):
    err_files = []
    count = 0
    seed_folders = glob.glob(output_dir + '/seed*')
    for folder in seed_folders:
        err_files += glob.glob(folder + '/' + pattern)

    logging.info('{} err files\n{}'.format(len(err_files), pprint.pformat(err_files)))

    exclude_whitelist = not is_sync_var
    err_map = {}
    for p in err_files:
        with open(p, 'r') as f:
            contents = f.read().strip().split('\n\n')

            for content in contents:
                content = content.strip()

                # skip possible empty contents
                if not content:
                    continue

                # skip benign inconsistencies in whitelists
                if exclude_whitelist and is_in_white_list(content):
                    continue

                count += 1
                if p not in err_map:
                    err_map[p] = [content]
                else:
                    err_map[p].append(content)

    return err_map, count

def _find_bugs_by_type_in_outputs(output_dir: str, report_dir: str,
                                  pattern: str, exclude_whitelist: bool,
                                  output_file: str, save_reports=True):
    inconsistency_map, n_bugs = find_errs(
        output_dir, pattern, exclude_whitelist
    )

    if save_reports:
        summarized_trace_path = os.path.join(report_dir, output_file)
        logging.info('{} PM inconsistencies (candidates) saved in {}'.format(
            n_bugs, summarized_trace_path
        ))

        with open(summarized_trace_path, 'w') as f:
            for k, v in inconsistency_map.items():
                for r in v:
                    f.write('[from {}]\n'.format(k))
                    f.write(str(r) + '\n\n\n')

    return inconsistency_map

def _check_buglist(err_map: Dict, bug_list: List, is_sync_var: bool):
    found_unique_bugs = set()
    for k, v in err_map.items():
        for trace in v:
            if is_sync_var:
                # Search synchronization inconsistency by locking
                for bug in bug_list:
                    if bug[0] in trace:
                        # Though the uniqueness is confirmed by bug[1] (manual hints),
                        # it's OK to directly leverage the locking instructions (bug[0]) to
                        # determine the uniqueness or just disable the uniqueness checking
                        found_unique_bugs.add(bug[1])
                        break
            else:
                # Search inter-/intra- thread inconsistency by the writer/reader pair
                trace_begin = trace.find('UWR')
                assert trace_begin != -1
                _, pm_write, pm_read, _ = trace[trace_begin:].split('\n', 3)

                for bug in bug_list:
                    if bug[0] in pm_write and bug[1] in pm_read:
                        # Though the uniqueness is confirmed by bug[2] (manual hints),
                        # it's OK to directly leverage the store instructions (bug[0]) to
                        # determine the uniqueness or just disable the uniqueness checking
                        found_unique_bugs.add(bug[2])
                        break
    logging.debug('found_unique_bugs: ' + str(found_unique_bugs))
    return len(found_unique_bugs)

def find_bugs_in_outputs(output_dir: str, report_dir: str, save_reports=True):
    if save_reports and not os.path.exists(report_dir):
        os.mkdir(report_dir)
    ret = []

    i_map = _find_bugs_by_type_in_outputs(
        output_dir, report_dir, INTERTHREAD_INCONSISTENCY_FILE_PATTERN,
        False, 'inter-inconsistency.log', save_reports
    )
    ret.append(_check_buglist(i_map, buglist.inter_thread_inconsistency_locs, False))

    i_map = _find_bugs_by_type_in_outputs(
        output_dir, report_dir, SYNC_INCONSISTENCY_FILE_PATTERN,
        True, 'sync-inconsistency.log', save_reports
    )
    ret.append(_check_buglist(i_map, buglist.sync_inconsistency_locs, True))

    i_map = _find_bugs_by_type_in_outputs(
        output_dir, report_dir, INTRATHREAD_INCONSISTENCY_FILE_PATTERN,
        False, 'intra-inconsistency.log', save_reports
    )
    ret.append(_check_buglist(i_map, buglist.intra_thread_inconsistency_locs, False))

    i_map = _find_bugs_by_type_in_outputs(
        output_dir, report_dir, INTERTHREAD_INCONSISTENCY_CANDIDATE_FILE_PATTERN,
        False, 'inter-inconsistency-candidate.log', save_reports
    )
    ret.append(_check_buglist(i_map, buglist.other_bug_locs, False))

    return ret

if __name__ == '__main__':
    enable_coloring_in_logging()

    # setup argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--log', default='ERROR',
        help='The logging level for python (default=ERROR)'
    )

    parser.add_argument(
        'output_dir', help='The directory of fuzzing outputs'
    )
    parser.add_argument(
        'report_dir', nargs='?', default='',
        help=(
            'The directory to store summarized reports. '
            'Skip the report storage if this argument is not set'
        )
    )

    args = parser.parse_args()

    loglevel = args.log
    numeric_level = getattr(logging, loglevel.upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=numeric_level
    )

    save_reports = args.report_dir != ''
    n_bugs = find_bugs_in_outputs(args.output_dir, args.report_dir, save_reports)
    logging.info("bugs: " + str(n_bugs))
    print(''.join(['{:>7d}'.format(x) for x in n_bugs]))
