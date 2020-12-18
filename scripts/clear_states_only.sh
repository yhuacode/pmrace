#!/bin/bash
echo 'Clear shared states but keep the "output" folder (for validation)'
echo '---------------------------------------------------------------'
echo '1. clear statistics in shared memory'
echo '../instrument/hook_ctr_cli free'
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
echo "$SCRIPTPATH/../instrument/hook_ctr_cli free"
$SCRIPTPATH/../instrument/hook_ctr_cli free

echo '---------------------------------------------------------------'
echo '2. remove pm pool file(s)'
echo 'rm -f /mnt/pmem0/pmem_pool_* /mnt/pmem0/pmrace/pmem_pool_* pmem_pool_* pmem_pool'
rm -f /mnt/pmem0/pmem_pool_* /mnt/pmem0/pmrace/pmem_pool_* pmem_pool_* pmem_pool

echo '---------------------------------------------------------------'
echo '3. free unused shared memory allocations if exist'
ipcs -m | tail -n +4 | awk '{if ($6 == 0) print $2;}' > sm.txt

while IFS= read -r line; do
        if [ ! -z $line ]
        then
                ipcrm -m $line && echo "rm shmid-$line"
        fi
done < sm.txt
rm -f sm.txt

echo '---------------------------------------------------------------'
echo 'done!'
