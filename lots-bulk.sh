#!/bin/sh
IDX=0;
while :; do
    rm -f morphis.log;
    python3 node.py -l logging-prod2.ini --bind 127.0.0.2:6${IDX}00 --addpeer 127.0.0.2:7002 --nn 2${IDX}00 --nodecount 100 --dbpoolsize 2 --cleartexttransport --dumptasksonexit --parallellaunch --dburl postgresql://m1:2d8VhzVIovxZy@pg1/m1 --dm &
#    sleep 1
    read
    mv morphis.log morphis-${IDX}.log

    IDX=$((IDX+1))
    if [ $IDX == 8 ]; then
        break
    fi
done
