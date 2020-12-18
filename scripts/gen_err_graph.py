from typing import List, Tuple, Dict

import shutil
import os
import glob
import json
import logging
import random
import time
import pprint
import sys

# importing the required module
import matplotlib.pyplot as plt
import numpy as np

from collections import namedtuple

import config

from fuzz_probe import Record
from util import multiplex_logging, execute0, enable_coloring_in_logging, ProgramError
from trace_walker import TraceRecord
from fuzz_exec import DFSanRecord
from whitelist import WHITELIST_LOCS


ERROR_RECORD_PATH = '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---race.csv.parsed.err'
INTERTHREAD_INCONSISTENCY_FILE_PATTERN = '*race.csv.parsed.err'

UNFLUSHED_RECORD_PATH = '{o_dir}/seed{seed_id}/seed{seed_id}-inter{inter_id}-run{run_id}---unflushed.csv.parsed.err'
INTRATHREAD_INCONSISTENCY_FILE_PATTERN = '*unflushed.csv.parsed.err'

SYNC_INCONSISTENCY_FILE_PATTERN = '*sync.parsed'

def is_in_white_list(content: str):
    trace_begin = content.find('UWR')
    assert trace_begin != -1

    for line in WHITELIST_LOCS:
        found = content.find(line, trace_begin)
        if found != -1:
            return True

    return False


def find_errs(output_dir: str, pattern: str, exclude_whitelist=True):
    err_files = []
    count = 0
    seed_folders = glob.glob(output_dir + '/seed*')
    for folder in seed_folders:
        err_files += glob.glob(folder + '/' + pattern)

    logging.info('{} err files\n{}'.format(len(err_files), pprint.pformat(err_files)))

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

def count_err(output_dir: str, r: Record, err_map: Dict, path_pattern: str):
    path = path_pattern.format(
        o_dir=output_dir, seed_id=r.seed_id, inter_id=r.inter_id, run_id=r.runs
    )

    if path in err_map:
        return len(err_map[path])
    else:
        return 0

def get_sorted_progress(output_dir: str, path_pattern: str, err_pattern: str):
    err_map, _ = find_errs(output_dir, err_pattern)

    files = sorted(glob.glob(output_dir + '/cov_incr-worker*.csv'))
    logging.info('Found record files: ' + pprint.pformat(files))

    outs, _ = execute0(['cat'] + files)

    title_line = config.COV_INCR_RECORD_TEMPLATE.format(
        *config.RECORD_COLUMNS
    )

    cfg_cov = 0
    dfg_cov = 0
    alias_cov = 0
    records = []

    total_inconsistency = 0

    lines = outs.strip().split('\n')
    for line in lines:
        r = Record(*[x for x in line.split(',')])

        cfg_cov += int(r.cfg_cov_incr)
        dfg_cov += int(r.dfg_cov_incr)
        alias_cov += int(r.alias_cov_incr)

        n_inconsistency = 0
        if int(r.alias_cov_incr) > 0:
            n_inconsistency = count_err(output_dir, r, err_map, path_pattern)

        total_inconsistency += n_inconsistency

        records.append((int(r.tid), r, n_inconsistency))

    logging.info(
        '\t total: runs = {}, cfg_cov = {}, dfg_cov = {}, alias_cov = {}, inconsistency = {}'
        .format(
            len(lines), cfg_cov, dfg_cov, alias_cov, total_inconsistency
        )
    )

    results = sorted(records, key=lambda x: x[0])
    assert len(results) > 1, str(results)

    elapsed_seconds = results[-1][0] - results[0][0]
    logging.info(
        '\t elapsed time: {} seconds'.format(elapsed_seconds)
    )

    return results

def plot_one_scheme(data, label: str):
    # starting timestamp
    t_start = data[0][0]

    # x values
    x_time = []

    total_UWR = 0

    # y values
    n_UWR = []

    for t in data:
        x_time.append(t[0] - t_start)

        total_UWR += t[2]
        n_UWR.append(total_UWR)

    logging.info('total_UWR for {}: {}'.format(
        label, total_UWR
    ))

    plt.plot(x_time, n_UWR, label=label)
    return x_time, n_UWR


def get_uwr_progress_fig(fig_path: str, title: str):
    axes = plt.gca()
    axes.set_xlim([0, None])

    plt.xlabel('Time (seconds)')
    plt.title(title)

    plt.legend()
    plt.savefig(fig_path)

    logging.info('plot saved in ' + fig_path)

def save_record(x1, y1, x2, y2, path: str):
    group1 = []
    group2 = []

    y = -1
    for i in range(len(x1)):
        if y1[i] != y:
            group1.append((x1[i], y1[i]))
            y = y1[i]
    if x1[-1] != group1[-1][0] or y1[-1] != group1[-1][1]:
        group1.append((x1[-1], y1[-1]))

    y = -1
    for i in range(len(x2)):
        if y2[i] != y:
            group2.append((x2[i], y2[i]))
            y = y2[i]
    if x2[-1] != group2[-1][0] or y2[-1] != group2[-1][1]:
        group2.append((x2[-1], y2[-1]))

    n = max(len(group1), len(group2))

    with open(path, 'w') as f:
        for i in range(n):
            n1 = ''
            n2 = ''
            n3 = ''
            n4 = ''
            if i < len(group1):
                n1 = group1[i][0]
                n2 = group1[i][1]
            if i < len(group2):
                n3 = group2[i][0]
                n4 = group2[i][1]

            f.write('{},{},{},{}\n'.format(n1, n2, n3, n4))
        logging.info('data saved in ' + path)

def plot_inter_thread_inconsistency(argv):
    # exe path1 [path2] fig_path
    title = 'Number of Inter-thread Inconsistency'

    delay_injection_data = get_sorted_progress(sys.argv[1], ERROR_RECORD_PATH, INTERTHREAD_INCONSISTENCY_FILE_PATTERN)
    x1, y1 = plot_one_scheme(delay_injection_data, 'Delay')

    if len(sys.argv) > 3:
        pmrace_data = get_sorted_progress(sys.argv[2], ERROR_RECORD_PATH, INTERTHREAD_INCONSISTENCY_FILE_PATTERN)
        x2, y2 = plot_one_scheme(pmrace_data, 'PMRace')

        get_uwr_progress_fig(sys.argv[3], title)
        save_record(x1, y1, x2, y2, sys.argv[4])
    else:
        get_uwr_progress_fig(sys.argv[2], title)

def plot_intra_thread_inconsistency(argv):
    # exe path1 [path2] fig_path
    title = 'Number of Intra-thread Inconsistency'

    delay_injection_data = get_sorted_progress(sys.argv[1], UNFLUSHED_RECORD_PATH, INTRATHREAD_INCONSISTENCY_FILE_PATTERN)
    x1, y1 = plot_one_scheme(delay_injection_data, 'Delay')

    if len(sys.argv) > 3:
        pmrace_data = get_sorted_progress(sys.argv[2], UNFLUSHED_RECORD_PATH, INTRATHREAD_INCONSISTENCY_FILE_PATTERN)
        x2, y2 = plot_one_scheme(pmrace_data, 'PMRace')

        get_uwr_progress_fig(sys.argv[3], title)
        save_record(x1, y1, x2, y2, sys.argv[4])
    else:
        get_uwr_progress_fig(sys.argv[2], title)

if __name__ == '__main__':
    enable_coloring_in_logging()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.INFO
    )

    ###########################################################################
    # [print traces]
    # This code snippet is used to aggregate the reports of
    # inter-thread inconsistency.

    # usage:
    #     output_dir

    #     output_dir: the directory of output in pmrace
    rs_map, n = find_errs(sys.argv[1], INTERTHREAD_INCONSISTENCY_FILE_PATTERN)
    logging.info('Found {} PM Inter-thread Inconsistencies'.format(n))
    summarized_trace_path = os.path.join(sys.argv[1], 'inter-inconsistency.log')
    with open(summarized_trace_path, 'w') as f:
        for k, v in rs_map.items():
            for r in v:
                f.write(str(r) + '\n')
    logging.info('Summarized in ' + summarized_trace_path)

    ###########################################################################
    # [print traces]
    # This code snippet is used to aggregate the reports of
    # synchronization inconsistency.

    # usage:
    #     output_dir

    #     output_dir: the directory of output in pmrace
    rs_map, n = find_errs(sys.argv[1], SYNC_INCONSISTENCY_FILE_PATTERN, False)
    logging.info('Found {} PM Synchronization Inconsistencies'.format(n))
    summarized_trace_path = os.path.join(sys.argv[1], 'sync-inconsistency.log')
    with open(summarized_trace_path, 'w') as f:
        for k, v in rs_map.items():
            for r in v:
                f.write(str(r) + '\n')
    logging.info('Summarized in ' + summarized_trace_path)


    ###########################################################################
    # [plot and save the duration for inter-thread inconsistency]
    # This code snippet is used to demonstrate the comparision of
    # two schemes, e.g., delay injection and pmrace, in terms of
    # the duration to detect inter-thread inconsistency. We use
    # matplotlib.pyplot the draw the draft figure and save the raw data.

    # usage:
    #     dir1 [dir2] fig_path fig_csv_path

    #     dir1: the output directory of the first scheme, e.g., delay injection
    #     dir1: the output directory of the second scheme, e.g., pmrace
    #     fig_path: the path of a demo figure to show the results
    #     fig_csv_path: the raw data used in the figure
    # plot_inter_thread_inconsistency(sys.argv)


    ###########################################################################
    # [plot and save the duration for intra-thread inconsistency]
    # This code snippet is used to demonstrate the comparision of
    # two schemes, e.g., delay injection and pmrace, in terms of
    # the duration to detect INTRA-thread inconsistency. We use
    # matplotlib.pyplot the draw the draft figure and save the raw data.

    # usage:
    #     dir1 [dir2] fig_path fig_csv_path

    #     dir1: the output directory of the first scheme, e.g., delay injection
    #     dir1: the output directory of the second scheme, e.g., pmrace
    #     fig_path: the path of a demo figure to show the results
    #     fig_csv_path: the raw data used in the figure
    # plot_intra_thread_inconsistency(sys.argv)
