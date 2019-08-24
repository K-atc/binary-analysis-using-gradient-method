#!/bin/bash 

echo "[*]" $0 $@

if [ $# -eq 0 ]; then
    echo "usage: $0 SOLVER_SAGE_FILE"
    exit
fi

SOLVER_SAGE_FILE=$1

cd sample
make
cd - > /dev/null

### Remove virtual file system
rm -rf ./fs-*

export PYTHONPATH=$PWD

if [ -z $TIME ]; then
    sage $@
else
    /usr/bin/time -v sage $@
fi