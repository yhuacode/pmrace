from typing import List, Tuple, Dict

import config


P_CLHT_CMD_TEMPLATE = './driver {nthreads}'
MEMCACHED_CMD_TEMPLATE = './memcached -p {port} -U {port} -A -o pslab_force,pslab_file={pool},pslab_policy=pmem'
CCEH_CMD_TEMPLATE = './bin/cceh {pool} {nthreads}'
FAST_FAIR_CMD_TEMPLATE = './btree_concurrent -p {pool} -t {nthreads}'
CLEVEL_CMD_TEMPLATE = './clevel_hash_ycsb {pool} {nthreads}'

MEMCACHED_RECOVER_CMD_TEMPLATE = './memcached -p {port} -U {port} -A -o pslab_recover,pslab_force,pslab_policy=pmem,pslab_file={pool}'

P_CLHT_THREAD_NUM = 4
CCEH_THREAD_NUM = 4
FAST_FAIR_THREAD_NUM = 4
CLEVEL_THREAD_NUM = 4

MEMCACHED_START_PORT = 11227
MEMCACHED_PORT_STEP = 16


def gen_pclht_cmd(worker_id: int) -> List[str]:
    cmd = P_CLHT_CMD_TEMPLATE.format(nthreads=P_CLHT_THREAD_NUM)
    return cmd.strip().split()

def gen_memcached_cmd(worker_id: int) -> List[str]:
    port_num = MEMCACHED_START_PORT + MEMCACHED_PORT_STEP * worker_id
    pool_name = config.PMEM_POOL_PATH_PREFIX + str(worker_id)
    cmd = MEMCACHED_CMD_TEMPLATE.format(port=port_num, pool=pool_name)
    return cmd.strip().split()

def gen_cceh_cmd(worker_id: int) -> List[str]:
    pool_name = config.PMEM_POOL_PATH_PREFIX + str(worker_id)
    cmd = CCEH_CMD_TEMPLATE.format(nthreads=CCEH_THREAD_NUM, pool=pool_name)
    return cmd.strip().split()

def gen_fast_fair_cmd(worker_id: int) -> List[str]:
    pool_name = config.PMEM_POOL_PATH_PREFIX + str(worker_id)
    cmd = FAST_FAIR_CMD_TEMPLATE.format(nthreads=FAST_FAIR_THREAD_NUM, pool=pool_name)
    return cmd.strip().split()

def gen_clevel_cmd(worker_id: int) -> List[str]:
    pool_name = config.PMEM_POOL_PATH_PREFIX + str(worker_id)
    cmd = CLEVEL_CMD_TEMPLATE.format(nthreads=CLEVEL_THREAD_NUM, pool=pool_name)
    return cmd.strip().split()


def gen_pclht_recover_cmd(worker_id: int, pool_name: str) -> List[str]:
    return gen_pclht_cmd(worker_id)

def gen_memcached_recover_cmd(worker_id: int, pool_name: str) -> List[str]:
    port_num = MEMCACHED_START_PORT + MEMCACHED_PORT_STEP * worker_id
    cmd = MEMCACHED_RECOVER_CMD_TEMPLATE.format(port=port_num, pool=pool_name)
    return cmd.strip().split()

def gen_cceh_recover_cmd(worker_id: int, pool_name: str) -> List[str]:
    cmd = CCEH_CMD_TEMPLATE.format(nthreads=CCEH_THREAD_NUM, pool=pool_name)
    return cmd.strip().split()

def gen_fast_fair_recover_cmd(worker_id: int, pool_name: str) -> List[str]:
    cmd = FAST_FAIR_CMD_TEMPLATE.format(nthreads=FAST_FAIR_THREAD_NUM, pool=pool_name)
    return cmd.strip().split()

# def gen_clevel_recover_cmd(worker_id: int, pool_name: str) -> List[str]:
#     cmd = CLEVEL_CMD_TEMPLATE.format(nthreads=CLEVEL_THREAD_NUM, pool=pool_name)
#     return cmd.strip().split()


AVALIABLE_PROGRAMS = [
    ('p-clht', gen_pclht_cmd),
    ('memcached', gen_memcached_cmd),
    ('cceh', gen_cceh_cmd),
    ('fast-fair', gen_fast_fair_cmd),
    ('clevel', gen_clevel_cmd),

    ('p-clht-re', gen_pclht_recover_cmd),
    ('memcached-re', gen_memcached_recover_cmd),
    ('cceh-re', gen_cceh_recover_cmd),
    ('fast-fair-re', gen_fast_fair_recover_cmd),
    # ('clevel-re', gen_clevel_recover_cmd),
]


class Program(object):

    def __init__(self, program: str, fuzzing: bool):
        if not fuzzing:
            program = program + '-re'

        func = None

        for _ in AVALIABLE_PROGRAMS:
            name, gen = _

            if program == name:
                func = gen
                break

        assert func is not None
        self.gen_cmd = func
