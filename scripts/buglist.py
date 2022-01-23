###############################################################################
# This file describes the locations of bugs found by PMRace.
#
# A record is identified by "(WRITE_LOC, READ_LOC, UNIQUE_BUG_ID)". The
# locations are specific line numbers of code after applying patches, while the
# locations in our ASPLOS 2022 paper denote the line numbers in original code.
# Though the line numbers in this bug list are slightly different from those
# in our paper, their corresponding codes are the same. "UNIQUE_BUG_ID"
# is the identifier for a unique bug, which is a group of bugs due to the same
# same store instruction in a PM program.
###############################################################################

inter_thread_inconsistency_locs = [
    #######################################################
    # P-CLHT in RECIPE

    # Reading non-persisted 'ht_off' field => data loss, ...
    ('src/clht_lb_res.c:804', 'src/clht_lb_res.c:877', 1),
    ('src/clht_lb_res.c:804', 'src/clht_lb_res.c:717', 1),
    ('src/clht_lb_res.c:804', 'src/clht_lb_res.c:373', 1),
    ('src/clht_lb_res.c:804', 'src/clht_lb_res.c:431', 1),
    ('src/clht_lb_res.c:804', 'src/clht_lb_res.c:578', 1),
    ('src/clht_lb_res.c:804', 'src/clht_lb_res.c:528', 1),
    ('src/clht_lb_res.c:804', 'src/clht_gc.c:103', 1),
    ('src/clht_lb_res.c:804', 'src/clht_gc.c:132', 1),
    ('src/clht_lb_res.c:804', 'src/clht_gc.c:154', 1),

    #######################################################
    # FAST&FAIR

    # Reading non-persisted node pointer => inserting items
    ('src/btree.h:560', 'src/btree.h:876', 1),
    ('src/btree.h:560', 'src/btree.h:878', 1),
    ('src/btree.h:560', 'src/btree.h:886', 1),

    #######################################################
    # memcached-pmem

    # Reading non-persisted "prev" field of items => writing “slabs_clsid” field
    ('items.c:423', 'items.c:464', 1),
    ('items.c:423', 'items.c:1160', 1),

    # Reading non-persisted "next" field of items => writing “it_flags” field
    ('slabs.c:554', 'slabs.c:417', 2),

    # Reading non-persisted "it_flags" field of items => writing item values
    ('items.c:1096', 'memcached.c:2825', 3),
    ('items.c:1096', 'memcached.c:2806', 3),

    # Reading non-persisted "slabs_clsid" field of items => writing "slabs_clsid" of other items
    ('items.c:627', 'items.c:623', 4),

    # Reading non-persisted item values => writing item values
    ('memcached.c:4293', 'libpmem2/x86_64/memcpy/memcpy_avx.h:56', 5),
    ('memcached.c:4293', 'libpmem2/x86_64/memcpy/memcpy_avx.h:57', 5),

    # Reading non-persisted item values => writing item values
    ('memcached.c:4294', 'libpmem2/x86_64/memcpy/memcpy_avx.h:56', 6),
    ('memcached.c:4294', 'libpmem2/x86_64/memcpy/memcpy_avx.h:57', 6),
]

intra_thread_inconsistency_locs = [
    #######################################################
    # P-CLHT in RECIPE

    # Reading non-persisted 'table_new' field => leakage for the old table
    ('src/clht_lb_res.c:808', 'src/clht_gc.c:190', 1),

    # Reading non-persisted 'table_off' field => leakage for the new table
    ('src/clht_lb_res.c:320', 'src/clht_lb_res.c:321', 2),
    ('src/clht_lb_res.c:320', 'src/clht_lb_res.c:626', 2),

    #######################################################
    # Clevel Hashing

    # Reading non-persisted 'meta' => PM allocation for level objects
    ('detail/compound_pool_ptr.hpp:61', 'detail/compound_pool_ptr.hpp:136', 1),

    #######################################################
    # CCEH

    # Reading non-persisted 'capacity' => PM allocation for segments
    ('src/CCEH.h:167', 'src/CCEH.cpp:183', 1),
]

non_reported = [
    #######################################################
    # P-CLHT in RECIPE

    # Cross-thread reading non-persisted 'ht_oldest' field
    ('src/clht_gc.c:199', 'src/clht_gc.c:186'),

    # Cross-thread reading non-persisted 'table_new' field
    ('src/clht_lb_res.c:808', 'src/clht_gc.c:190')
]

sync_inconsistency_locs = [
    #######################################################
    # P-CLHT in RECIPE

    # bucket locks
    ('src/clht_lb_res.c:661', 1),
    ('src/clht_lb_res.c:443', 1),

    #######################################################
    # CCEH

    # segment locks
    ('src/CCEH.h:88', 1)
]

other_bug_locs = [
    #######################################################
    # P-CLHT in RECIPE

    # Unnecessary (redundant) bucket initialization
    ('src/clht_lb_res.c:335', 'src/clht_lb_res.c:633', 1)
]
