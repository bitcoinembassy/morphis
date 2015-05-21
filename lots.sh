#!/bin/sh

rm -f morphis-*.log

IDX=0;
while :; do
    rm -f morphis.log;
    python3 node.py -l logging-prod.ini --bind 127.0.0.1:6000 --addpeer 127.0.0.1:7002 --nn 2000 --nodecount 10 --dbpoolsize 10 --cleartexttransport --dumptasksonexit --parallellaunch --dburl postgresql://m1:2d8VhzVIovxZy@pg1/m1 --dm --instanceoffset ${IDX} &
    sleep 0.5
    mv morphis.log morphis-${IDX}.log

    IDX=$((IDX+10))
    if [ $IDX == 200 ]; then
        break
    fi
done
