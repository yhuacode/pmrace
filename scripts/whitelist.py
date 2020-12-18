WHITELIST_LOCS = [
    # logging in PMDK allocation
    'pmrace/deps/pmdk/src/libpmemobj/obj.c:2200',

    # logging in PMDK allocation
    'pmrace/deps/pmdk/src/libpmemobj/obj.c:2920',

    # checksum in memcached-pmem
    'memcached-pmem/pslab.c:122',
]