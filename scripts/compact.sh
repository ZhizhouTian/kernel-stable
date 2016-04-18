echo 3 > /sys/block/zram0/max_comp_streams
echo $((400*1024*1024)) > /sys/block/zram0/disksize
mkswap /dev/zram0
swapon /dev/zram0

./costmem -c 256000 -b 128 -o 0 &
./cost_mem_nolock -c 256000 -b 128 &
./cost_mem_nolock -c 256000 -b 128 &
./cost_mem_nolock -c 256000 -b 128 &

sleep 10

kill -9 `pidof cost_mem_nolock`

./cost_mem_nolock -c 256000 -b 128 &

sleep 30

cat /proc/meminfo

for i in `seq 1 8`; 
do
	dd if=/dev/urandom of=mnt/test$i.txt bs=128M count=1 &
done

wait `pidof dd` 

for i in `seq 1 2 8`; 
do
	rm -rf mnt/test$i.txt
done
fstrim -v mnt 

cat /proc/meminfo

echo "init"
cat /proc/buddyinfo

echo "compaction"
echo 1 > /proc/sys/vm/compact_memory
cat /proc/buddyinfo
cat /proc/meminfo
