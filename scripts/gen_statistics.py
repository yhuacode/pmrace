from typing import List, Tuple, Dict

import os
import glob
import logging
import pprint
import re
import argparse

from util import enable_coloring_in_logging
from whitelist import WHITELIST_LOCS
from find_bugs import find_bugs_in_outputs


# '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---race.csv.parsed'
INTERTHREAD_INCONSISTENCY_CANDIDATE_FILE_PATTERN = '*race.csv.parsed'

# '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---race.csv.parsed.err'
INTERTHREAD_INCONSISTENCY_FILE_PATTERN = '*race.csv.parsed.err'

# '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---unflushed.csv.parsed'
INTRATHREAD_INCONSISTENCY_CANDIDATE_FILE_PATTERN = '*unflushed.csv.parsed'

# '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---unflushed.csv.parsed.err'
INTRATHREAD_INCONSISTENCY_FILE_PATTERN = '*unflushed.csv.parsed.err'

# '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---sync.parsed'
SYNC_INCONSISTENCY_FILE_PATTERN = '*sync.parsed'


prog = re.compile(r'seed\d+-inter\d+-run\d+')

def is_in_white_list(content: str):
    trace_begin = content.find('UWR')
    assert trace_begin != -1

    for line in WHITELIST_LOCS:
        found = content.find(line, trace_begin)
        if found != -1:
            return True

    return False

def _find_files(output_dir: str, pattern: str):
    err_files = []
    seed_folders = glob.glob(output_dir + '/seed*')
    for folder in seed_folders:
        err_files += glob.glob(folder + '/' + pattern)

    logging.debug('{} err files\n{}'.format(len(err_files), pprint.pformat(err_files)))
    return err_files

def find_inconsistencies_or_candidates(output_dir: str, pattern: str, is_sync_var=False):
    err_files = _find_files(output_dir, pattern)
    err_map = {}
    count = 0
    n_whitelist = 0

    exclude_whitelist = not is_sync_var
    for p in err_files:
        with open(p, 'r') as f:
            contents = f.read().strip().split('\n\n')

            for content in contents:
                content = content.strip()

                # skip possible empty contents
                if not content:
                    continue

                if exclude_whitelist and is_in_white_list(content):
                    n_whitelist += 1
                    continue

                count += 1
                if p not in err_map:
                    err_map[p] = [content]
                else:
                    err_map[p].append(content)

    return err_map, count, n_whitelist

def find_dfsan_records_in_trace(trace: str):
    lines = trace.strip().split('\n')
    assert len(lines) > 2

    DFSAN_PATTERN = 'hash: dfsan-'
    ALIAS_PATTERN = 'hash: alias-'
    dfsan_records = []
    alias_record = None
    for line in lines:
        if DFSAN_PATTERN in line:
            dfsan_records.append(line.split(':')[1].strip())
        elif ALIAS_PATTERN in line and 'writer' not in line:
            assert alias_record is None
            alias_record = line.split(':')[1].strip()

    return alias_record, dfsan_records

def find_inconsistency(output_dir: str, pattern: str):
    err_map, n, n_whitelist = find_inconsistencies_or_candidates(output_dir, pattern)
    err_objs = {}
    for k, v in err_map.items():
        m = prog.search(k)
        assert m

        folder = m.group(0)
        assert folder not in err_objs
        err_objs[folder] = []
        for content in v:
            alias_record, dfsan_records = find_dfsan_records_in_trace(content)
            err_objs[folder].append((alias_record, dfsan_records, content))

    return err_objs, n, n_whitelist

def _check_validation(validate_dir: str, folder: str, tag: str):
    TAG_TRUE_FILE = '{v_dir}/{folder}/{tag}---stacktrace.true.err'
    TAG_FALSE_FILE = '{v_dir}/{folder}/{tag}---stacktrace.false.err'

    temp = TAG_TRUE_FILE.format(v_dir=validate_dir, folder=folder, tag=tag)
    if os.path.exists(temp):
        logging.debug('\ttrue bug: ' + temp)
        return 1

    temp = TAG_FALSE_FILE.format(v_dir=validate_dir, folder=folder, tag=tag)
    if os.path.exists(temp):
        logging.debug('\tfalse positive: ' + temp)
        return -1

    logging.debug('\tunknown DFSAN')
    return 0

def find_validate_dfsan_results(validate_dir: str, err_objs: Dict):
    n_false_positives = 0
    n_true_bugs = 0
    for folder, v in err_objs.items():
        for pair in v:
            alias_record, dfsan_records, content = pair
            logging.debug('Checking {} => {}'.format(alias_record, dfsan_records))
            stat = 0
            found_true_dfsan = False
            for dfsan_tag in dfsan_records:
                r =  _check_validation(validate_dir, folder, dfsan_tag)
                if r == 1:
                    found_true_dfsan = True
                stat += r

            # all dfsan are false
            if stat == -len(dfsan_records):
                logging.warning('Found one false positive')
                n_false_positives += 1
            elif found_true_dfsan:
                logging.warning('Found one true bug')
                n_true_bugs += 1
                logging.debug(content)
            else:
                logging.warning('Found one bug need to be checked')
                logging.debug(content)
    return n_false_positives, n_true_bugs

def find_validate_sync_var_results(output_dir: str, validate_dir: str):
    err_files = _find_files(output_dir, SYNC_INCONSISTENCY_FILE_PATTERN)
    sync_var_imgs = []
    for p in err_files:
        sync_var_img_folder = p.split('---')[0]
        sync_var_imgs += glob.glob(sync_var_img_folder + '/pmem-sync*.img')
    logging.debug('sync_var_imgs: {}'.format(sync_var_imgs))

    n_false_positives = 0
    n_true_bugs = 0
    for sync_var_img_path in sync_var_imgs:
        _, folder, sync_var_img_name = sync_var_img_path.rsplit('/', 2)
        sync_var_tag = sync_var_img_name.split('.')[0]
        r = _check_validation(validate_dir, folder, sync_var_tag)
        if r == -1:
            n_false_positives += 1
        elif r == 1:
            n_true_bugs += 1

    return n_false_positives

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
        'validate_dir', nargs='?', default='',
        help=(
            'The directory of validation results to '
            'count the false positives'
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

    ret = []

    ###########################################################################
    ## count the number of inter-thread inconsistency candidates
    # n does not include n_whitelist
    # usage:
    #     output_dir

    _, n, n_whitelist = find_inconsistencies_or_candidates(args.output_dir, INTERTHREAD_INCONSISTENCY_CANDIDATE_FILE_PATTERN)
    logging.info('Found {} inter-thread inconsistency candidates (excluding {} filtered by whitelist)'.format(n, n_whitelist))
    ret.append(n)

    ###########################################################################
    ## count the number of inter-thread inconsistency
    # n does not include n_whitelist
    # usage:
    #     output_dir

    _, n, n_whitelist = find_inconsistencies_or_candidates(args.output_dir, INTERTHREAD_INCONSISTENCY_FILE_PATTERN)
    logging.info('Found {} inter-thread inconsistency (excluding {} filtered by whitelist)'.format(n, n_whitelist))
    ret.append(n)

    ###########################################################################
    ## count the number of synchronization inconsistency
    # usage:
    #     output_dir

    _, n, _ = find_inconsistencies_or_candidates(args.output_dir, SYNC_INCONSISTENCY_FILE_PATTERN, True)
    logging.info('Found {} sync inconsistency'.format(n))
    ret.append(n)

    ###########################################################################
    ## count the number of intra-thread inconsistency candidates
    # n does not include n_whitelist
    # usage:
    #     output_dir

    # _, n, n_whitelist = find_inconsistencies_or_candidates(args.output_dir, INTRATHREAD_INCONSISTENCY_CANDIDATE_FILE_PATTERN)
    # logging.error('Found {} intra-thread inconsistency candidates (excluding {} filtered by whitelist)'.format(n, n_whitelist))

    ###########################################################################
    ## count the number of intra-thread inconsistency
    # n does not include n_whitelist
    # usage:
    #     output_dir

    # _, n, n_whitelist = find_inconsistencies_or_candidates(args.output_dir, INTRATHREAD_INCONSISTENCY_FILE_PATTERN)
    # logging.error('Found {} intra-thread inconsistency (excluding {} filtered by whitelist)'.format(n, n_whitelist))

    ###########################################################################
    ## count the number of false positives for inter-thread inconsistencies
    # n does not include n_whitelist
    # usage:
    #     output_dir validate_dir

    n_false_positives = 0
    if args.validate_dir:
        err_objs, n, n_whitelist = find_inconsistency(args.output_dir, INTERTHREAD_INCONSISTENCY_FILE_PATTERN)
        n_false_positives, _ = find_validate_dfsan_results(args.validate_dir, err_objs)
        logging.info('false positives of inter-thread inconsistency: {}'.format(n_false_positives))
    ret.append(n_false_positives)

    ###########################################################################
    ## count the number of false positives for inter-thread inconsistencies
    # n does not include n_whitelist
    # usage:
    #     output_dir validate_dir

    n_false_positives = 0
    if args.validate_dir:
        n_false_positives = find_validate_sync_var_results(args.output_dir, args.validate_dir)
        logging.info('false positives of sync inconsistency: {}'.format(n_false_positives))
    ret.append(n_false_positives)

    ###########################################################################
    ## count the PM concurrency bugs
    # usage:
    #     output_dir
    r = find_bugs_in_outputs(args.output_dir, None, False)
    ret.append(r[0] + r[1])

    print(''.join(['{:>9d}'.format(x) for x in ret]))
