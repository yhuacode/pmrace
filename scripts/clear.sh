#!/bin/bash
echo 'Clear all the shared states and outputs of previous tests'
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
echo '3. clear output'
echo 'rm -rf output'
rm -rf output

echo '---------------------------------------------------------------'
echo '4. remove obj.json'
echo 'rm -f obj.json'
rm -f obj.json

echo '---------------------------------------------------------------'
echo '5. free unused shared memory allocations if exist'
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
