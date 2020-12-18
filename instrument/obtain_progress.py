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

import config

from fuzz_probe import Record
from util import multiplex_logging, execute0, enable_coloring_in_logging

def check_coverage(output_dir: str, cov_out='cov_sorted_realtime.csv'):
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

    lines = outs.strip().split('\n')
    for line in lines:
        r = Record(*[x for x in line.split(',')])

        cfg_cov += int(r.cfg_cov_incr)
        dfg_cov += int(r.dfg_cov_incr)
        alias_cov += int(r.alias_cov_incr)
        records.append((int(r.tid), line))

    logging.info(
        '\t total: runs = {}, cfg_cov = {}, dfg_cov = {}, alias_cov = {}'
        .format(
            len(lines), cfg_cov, dfg_cov, alias_cov
        )
    )
    with open(cov_out, 'w') as f:
        f.write(title_line + '\n')

        t_start = None
        t_end = None
        for idx, t in enumerate(sorted(records, key=lambda x: x[0])):
            if idx == 0:
                t_start = t
            t_end = t
            f.write(t[1] + '\n')

        f.write(',,,,{},{},{},{}'.format(
            len(lines), cfg_cov, dfg_cov, alias_cov
        ))

        if t_end:
            logging.info(
                '\t elapsed time: {} seconds'.format(t_end[0] - t_start[0])
            )


if __name__ == '__main__':
    enable_coloring_in_logging()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )

    check_coverage(sys.argv[1])