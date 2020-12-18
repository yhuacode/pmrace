from typing import List, Tuple, Dict

import os
import logging
import sys
import pprint
import json

import config

from collections import namedtuple

from util import execute0, enable_coloring_in_logging


class TraceRecord(object):

    def __init__(
        self, tag: str, pid1: str, pid2: str, hash: str,
        addr: str, size: str, src: str, dst: str):
        self.tag = tag
        self.pid1 = int(pid1)
        self.pid2 = int(pid2)
        self.hash = hash
        self.addr = int(addr, base=16)
        self.size = int(size)
        self.src = int(src)
        self.dst = int(dst)

        self.addr_end = self.addr + self.size

        self.src_raw = src
        self.dst_raw = dst

    def __repr__(self):
        return 'TraceRecord: tag={} pid1={} pid2={} hash={} addr={} size={} src={} dst={}'.format(
            self.tag, self.pid1, self.pid2, self.hash,
            hex(self.addr), self.size, self.src, self.dst
        )

    def is_overlap(self, other) -> bool:
        if ((self.addr <= other.addr and other.addr <= self.end) or
            (other.addr <= self.addr and self.addr <= other.end)):
            return True

        return False


class TraceWalker(object):

    def __init__(self, meta: Dict, pmdk: Dict):
        self.meta = meta
        self.pmdk = pmdk

        self.access_inst = None

        self.inst_map = {}
        self.nt_inst = set()

    def _prepare(self, records: List[TraceRecord]) -> None:
        for r in records:
            # prepare loc and source info for the src part
            if str(r.src) in self.meta['instructions']:
                r.src_loc = self.meta['instructions'][str(r.src)]['info']
                r.src_ir = self.meta['instructions'][str(r.src)]['repr']
                r.src_in_pmdk = False
            elif self.pmdk and str(r.src) in self.pmdk['instructions']:
                r.src_loc = self.pmdk['instructions'][str(r.src)]['info']
                r.src_ir = self.pmdk['instructions'][str(r.src)]['repr']
                r.src_in_pmdk = True

            # record possible nt-store
            if 'nontemporal' in r.src_ir:
                self.nt_inst.add(r.src)

            # prepare loc and source info for the dst part
            if str(r.dst) in self.meta['instructions']:
                r.dst_loc = self.meta['instructions'][str(r.dst)]['info']
                r.dst_ir = self.meta['instructions'][str(r.dst)]['repr']
                r.dst_in_pmdk = False
            elif self.pmdk and str(r.dst) in self.pmdk['instructions']:
                r.dst_loc = self.pmdk['instructions'][str(r.dst)]['info']
                r.dst_ir = self.pmdk['instructions'][str(r.dst)]['repr']
                r.dst_in_pmdk = True

            # record possible nt-store
            if 'nontemporal' in r.dst_ir:
                self.nt_inst.add(r.dst)

    def _update_inst_map(self, hval: int, addr: int, is_write: bool) -> None:
        assert hval not in self.nt_inst

        if hval not in self.inst_map:
            self.inst_map[hval] = {'readers': set(), 'writers': set()}

        if is_write:
            self.inst_map[hval]['writers'].add(addr)
        else:
            self.inst_map[hval]['readers'].add(addr)

    def _group_addr(
        self, records: List[TraceRecord], addr_set: Dict,
        is_alias: bool, shared_memory_addrs: set
    ) -> None:
        for r in records:
            if is_alias:
                shared_memory_addrs.add(r.addr)

            if r.addr not in addr_set:
                addr_set[r.addr] = {r.pid1: [r]}
            elif r.pid1 not in addr_set[r.addr]:
                addr_set[r.addr][r.pid1] = [r]
            else:
                addr_set[r.addr][r.pid1].append(r)

    def _group_records3(
        self, memdu_records: List[TraceRecord],
        alias_records: List[TraceRecord]
    ) -> List:
        addr_set = {}
        access_inst = {}
        shared_memory_addrs = set()

        self._prepare(memdu_records)
        self._prepare(alias_records)

        self._group_addr(memdu_records, addr_set, False, shared_memory_addrs)
        self._group_addr(alias_records, addr_set, True, shared_memory_addrs)

        # logging.debug('addr_set\n' + pprint.pformat(addr_set))

        for k, v in addr_set.items():
            if len(v.items()) > 2 or k in shared_memory_addrs:
                # lines = ['found one shared memory acccess in {}({})'.format(k, hex(k))]
                # for pid, rs in v.items():
                #     lines.append('pid1: ' + str(pid))
                #     for r in rs:
                #         lines.append('\t\ttag: {} pid2: {} size: {} src: {} {} dst: {} {}'
                #             .format(
                #                 r.tag, r.pid2, r.size, r.src, r.src_loc, r.dst, r.dst_loc
                #             )
                #         )
                # logging.debug('\n'.join(lines))

                access_inst[k] = {'writers': set(), 'readers': set(), 'priority': 0}



                # for pid, rs in v.items():
                #     for r in rs:
                #         if r.src not in self.nt_inst:
                #             access_inst[k]['priority'] += not r.src_in_pmdk
                #             src_tuple = (r.src, r.src_loc, r.src_ir, r.src_in_pmdk)
                #             if r.tag[1] == 'R':
                #                 access_inst[k]['readers'].add(src_tuple)
                #                 self._update_inst_map(r.src, k, False)
                #             else:
                #                 access_inst[k]['writers'].add(src_tuple)
                #                 self._update_inst_map(r.src, k, True)
                #         else:
                #             logging.debug('found nt-store {}: {}'.format(r.src, r.src_ir))

                #         if r.dst not in self.nt_inst:
                #             access_inst[k]['priority'] += not r.dst_in_pmdk
                #             dst_tuple = (r.dst, r.dst_loc, r.dst_ir, r.dst_in_pmdk)
                #             if r.tag[2] == 'R':
                #                 access_inst[k]['readers'].add(dst_tuple)
                #                 self._update_inst_map(r.dst, k, False)
                #             else:
                #                 access_inst[k]['writers'].add(dst_tuple)
                #                 self._update_inst_map(r.dst, k, True)
                #         else:
                #             logging.debug('found nt-store {}: {}'.format(r.dst, r.dst_ir))
                self._update_records(v, access_inst, k)


        # logging.debug('access_inst\n' + pprint.pformat(access_inst))


        self.access_inst = access_inst

        # self.priority_inst = sorted(
        #     access_inst.items(),
        #     key=lambda r: r[1]['priority'],
        #     reverse=True
        # )

    def get_injection_points(self) -> List:
        count = 0
        points = []
        priority_inst = sorted(
            self.access_inst.items(),
            key=lambda r: r[1]['priority'],
            reverse=True
        )

        for addr, obj in priority_inst:
            writer_insts = sorted(obj['writers'], key=lambda x: x[3])
            count += len(writer_insts)
            points.append({
                'priority': obj['priority'],
                'writers': writer_insts,
                'readers': list(obj['readers'])
            })

            if count >= config.INJECTION_POINT_LIMIT:
                break

        return points

    def _update_records(self, addrs: Dict, access_inst: Dict, k: int) -> None:
        for pid, rs in addrs.items():
            for r in rs:
                if r.src not in self.nt_inst:
                    access_inst[k]['priority'] += not r.src_in_pmdk
                    src_tuple = (r.src, r.src_loc, r.src_ir, r.src_in_pmdk)
                    if r.tag[1] == 'R':
                        access_inst[k]['readers'].add(src_tuple)
                        self._update_inst_map(r.src, k, False)
                    else:
                        access_inst[k]['writers'].add(src_tuple)
                        self._update_inst_map(r.src, k, True)
                else:
                    logging.debug('found nt-store {}: {}'.format(r.src, r.src_ir))

                if r.dst not in self.nt_inst:
                    access_inst[k]['priority'] += not r.dst_in_pmdk
                    dst_tuple = (r.dst, r.dst_loc, r.dst_ir, r.dst_in_pmdk)
                    if r.tag[2] == 'R':
                        access_inst[k]['readers'].add(dst_tuple)
                        self._update_inst_map(r.dst, k, False)
                    else:
                        access_inst[k]['writers'].add(dst_tuple)
                        self._update_inst_map(r.dst, k, True)
                else:
                    logging.debug('found nt-store {}: {}'.format(r.dst, r.dst_ir))


    def update_records(
        self, memdu_records: List[TraceRecord], alias_records: List[TraceRecord]
    ) -> None:
        addr_set = {}
        shared_memory_addrs = set()

        self._prepare(memdu_records)
        self._prepare(alias_records)

        self._group_addr(memdu_records, addr_set, False, shared_memory_addrs)
        self._group_addr(alias_records, addr_set, True, shared_memory_addrs)

        for k, v in addr_set.items():
            for pid, rs in v.items():
                for r in rs:
                    if r.src in self.inst_map:
                        # add addr_set[k] to self.access_inst
                        # and update inst_map
                        # TODO: one IR may be related to many addresses
                        all_addrs = self.inst_map[r.src]['readers'].union(
                            self.inst_map[r.src]['writers']
                        )
                        self._update_records(
                            addr_set[k], self.access_inst, list(all_addrs)[0]
                        )
                        continue
                    elif r.dst in self.inst_map:
                        # add addr_set[k] to self.access_inst
                        # update inst_map
                        # TODO: one IR may be related to many addresses
                        all_addrs = self.inst_map[r.dst]['readers'].union(
                            self.inst_map[r.dst]['writers']
                        )
                        self._update_records(
                            addr_set[k], self.access_inst, list(all_addrs)[0]
                        )
                        continue

        for r in alias_records:
            # alias records (and memdu records in the same addr set) may not
            # be recorded in previous runs, so we need to add these records.
            if r.src not in self.inst_map:
                self.access_inst[r.addr] = {
                    'writers': set(), 'readers': set(), 'priority': 0
                }
                self._update_records(
                    addr_set[r.addr], self.access_inst, r.addr
                )

        # if addr_set:
        #     self.priority_inst.sort(
        #         key=lambda r: r[1]['priority'],
        #         reverse=True
        #     )


    def _group_records2(self, records: List[TraceRecord]) -> None:
        writer_set = {}
        reader_set = {}

        addr_set = {}
        access_inst = {}

        for r in records:
            if str(r.src) in self.meta['instructions']:
                r.src_loc = self.meta['instructions'][str(r.src)]['info']
                r.src_in_pmdk = False
            elif self.pmdk and str(r.src) in self.pmdk['instructions']:
                r.src_loc = self.pmdk['instructions'][str(r.src)]['info']
                r.src_in_pmdk = True

            if str(r.dst) in self.meta['instructions']:
                r.dst_loc = self.meta['instructions'][str(r.dst)]['info']
                r.dst_in_pmdk = False
            elif self.pmdk and str(r.dst) in self.pmdk['instructions']:
                r.dst_loc = self.pmdk['instructions'][str(r.dst)]['info']
                r.dst_in_pmdk = True

            if r.addr not in addr_set:
                addr_set[r.addr] = {r.pid: [r]}
            elif r.pid not in addr_set[r.addr]:
                addr_set[r.addr][r.pid] = [r]
            else:
                addr_set[r.addr][r.pid].append(r)

        logging.debug('addr_set\n' + pprint.pformat(addr_set))

        for k, v in addr_set.items():
            if len(v.items()) > 2:
                lines = ['found one shared memory acccess in {}({})'.format(k, hex(k))]
                for pid, rs in v.items():
                    lines.append('pid: ' + str(pid))
                    for r in rs:
                        lines.append('\t\ttag: {} size: {} src: {} {} dst: {} {}'
                            .format(
                                r.tag, r.size, r.src, r.src_loc, r.dst, r.dst_loc
                            )
                        )
                logging.debug('\n'.join(lines))

                access_inst[k] = {'writers': set(), 'readers': set()}

                for pid, rs in v.items():
                    for r in rs:
                        src_tuple = (r.src, r.src_loc, r.src_in_pmdk)
                        dst_tuple = (r.dst, r.dst_loc, r.dst_in_pmdk)
                        if r.tag[1] == 'R':
                            access_inst[k]['readers'].add(src_tuple)
                        else:
                            access_inst[k]['writers'].add(src_tuple)

                        if r.tag[2] == 'R':
                            access_inst[k]['readers'].add(dst_tuple)
                        else:
                            access_inst[k]['writers'].add(dst_tuple)

        logging.debug('access_inst\n' + pprint.pformat(access_inst))


    def _group_records(self, records: List[TraceRecord]) -> None:
        writer_set = {}
        reader_set = {}

        ww_writers = set()

        # {
        #     writer1: {
        #         'loc': LOC,
        #         'flag': FLAG,
        #         reader1: record,
        #         reader2: record,
        #         ...
        #     },
        #     ...
        # }
        alias_readers = {}

        adjacent_writers = set()

        for r in records:
            if str(r.src) in self.meta['instructions']:
                r.src_loc = self.meta['instructions'][str(r.src)]['info']
                r.src_in_pmdk = False
            elif self.pmdk and str(r.src) in self.pmdk['instructions']:
                r.src_loc = self.pmdk['instructions'][str(r.src)]['info']
                r.src_in_pmdk = True

            if str(r.dst) in self.meta['instructions']:
                r.dst_loc = self.meta['instructions'][str(r.dst)]['info']
                r.dst_in_pmdk = False
            elif self.pmdk and str(r.dst) in self.pmdk['instructions']:
                r.dst_loc = self.pmdk['instructions'][str(r.dst)]['info']
                r.dst_in_pmdk = True

            if r.tag[1:] == 'WR' or r.tag[1:] == 'RW':
                if r.tag[1:] == 'WR':
                    r.reader = r.dst
                    r.reader_loc = r.dst_loc
                    r.reader_in_pmdk = r.dst_in_pmdk

                    r.writer = r.src
                    r.writer_loc = r.src_loc
                    r.writer_in_pmdk = r.src_in_pmdk
                else:
                    r.reader = r.src
                    r.reader_loc = r.src_loc
                    r.reader_in_pmdk = r.src_in_pmdk

                    r.writer = r.dst
                    r.writer_loc = r.dst_loc
                    r.writer_in_pmdk = r.dst_in_pmdk

                if r.writer not in writer_set:
                    writer_set[r.writer] = {
                        'loc': r.writer_loc,
                        'flag': r.writer_in_pmdk,
                        'count': 1
                    }
                else:
                    writer_set[r.writer]['count'] += 1

                if r.reader not in reader_set:
                    reader_set[r.reader] = {
                        'loc': r.reader_loc,
                        'flag': r.reader_in_pmdk,
                        'count': 1
                    }
                else:
                    reader_set[r.reader]['count'] += 1

                if r.writer not in alias_readers:
                    alias_readers[r.writer] = {
                        'loc': r.writer_loc,
                        'flag': r.writer_in_pmdk,
                        r.reader: r
                    }
                elif r.reader not in alias_readers[r.writer]:
                    alias_readers[r.writer][r.reader] = r

            else:
                if r.src < r.dst:
                    r.writers = (r.src, r.dst)
                elif r.src > r.dst:
                    r.writers = (r.dst, r.src)
                else:
                    r.writers = (r.src,)

                ww_writers.add(r.src)
                ww_writers.add(r.dst)

                adjacent_writers.add(r.writers)

        # logging.debug('writer_set: ' + pprint.pformat(writer_set))
        # logging.debug('reader_set: ' + pprint.pformat(reader_set))
        # logging.debug('alias_readers: ' + pprint.pformat(alias_readers))

        # logging.debug('ww_writers: ' + pprint.pformat(ww_writers))
        # logging.debug('adjacent_writers: ' + pprint.pformat(adjacent_writers))

        lines = []
        for k, v in writer_set.items():
            lines.append('hash: {}\tcount: {}\tloc: {}\tin_pmdk: {}'.format(
                # k, v, self.code['instructions'][str(k)]['info']
                k, v['count'], v['loc'], v['flag']
            ))
        logging.debug('writer_set\n{}'.format('\n'.join(lines)))

        lines = []
        for k, v in reader_set.items():
            lines.append('hash: {}\tcount: {}\tloc: {}\tin_pmdk: {}'.format(
                # k, v, self.code['instructions'][str(k)]['info']
                k, v['count'], v['loc'], v['flag']
            ))
        logging.debug('reader_set\n{}'.format('\n'.join(lines)))

        lines = []
        for w_hash, info in alias_readers.items():
            lines.append('writer: {}\tloc: {}\tin_pmdk: {}'.format(
                w_hash, info['loc'], info['flag']
            ))
            for k, v in info.items():
                # skip writer attributes (e.g., 'loc', 'flag')
                if type(k) == str:
                    continue

                lines.append('\t\treader: {}\tloc: {}\tin_pmdk: {}\ttag: {}'.format(
                    k, v.reader_loc, v.reader_in_pmdk, v.tag
                ))
        logging.debug('alias_readers\n{}'.format('\n'.join(lines)))

        # logging.debug('alias_readers\n' + pprint.pformat(alias_readers))
        logging.debug('ww_writers\n' + pprint.pformat(ww_writers))
        logging.debug('adjacent_writers\n' + pprint.pformat(adjacent_writers))

        logging.debug('end of grouping...\n\n\n')

        # lines = []
        # for w_hash, readers in alias_readers.items():
        #     lines.append('writer: {}\tloc: {}'.format(
        #         w_hash, self.code['instructions'][str(w_hash)]['info']
        #     ))
        #     for k, v in readers.items():
        #         lines.append('\treader: {}\tloc: {}\trecord: {}'.format(
        #             k, v, self.code['instructions'][str(k)]['info']
        #         ))
        # logging.debug('alias_readers\n{}'.format('\n'.join(lines)))


    def group_records(
        self, memdu_records: List[TraceRecord],
        alias_records: List[TraceRecord]
    ) -> None:
        self._group_records3(memdu_records, alias_records)

    def is_empty(self) -> bool:
        return not bool(self.inst_map)

    def clear(self) -> None:
        self.access_inst = None
        self.inst_map = {}



if __name__ == '__main__':
    enable_coloring_in_logging()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )

    lines = open(sys.argv[1]).read().strip().split('\n')[1:]
    memdu_records = [TraceRecord(*line.strip().split(',')) for line in lines]

    lines = open(sys.argv[2]).read().strip().split('\n')[1:]
    alias_records = [TraceRecord(*line.strip().split(',')) for line in lines]

    # obj.json
    with open(sys.argv[3], 'r') as f:
        meta = json.load(f)

    # PMDK
    with open(sys.argv[4], 'r') as f:
        pmdk = json.load(f)

    walker = TraceWalker(meta, pmdk)
    walker.group_records(memdu_records, alias_records)
    pts = walker.get_injection_points()
    priority_inst = sorted(
        walker.access_inst.items(),
        key=lambda r: r[1]['priority'],
        reverse=True
    )
    logging.debug('priority_inst\n' + pprint.pformat(priority_inst))
    logging.debug('inst_map\n' + pprint.pformat(walker.inst_map))
    logging.debug('injection points\n' + pprint.pformat(pts))
