#!/bin/bash 

if [ $# -eq 0 ]; then
    echo "usage: $0 SOLVER_SAGE_FILE"
    exit
fi

SOLVER_SAGE_FILE=$1

cd sample
make
cd - > /dev/null

rm -f *.sage.py

rm -rf ./fs-*/*

sage -preparse engine.sage && mv engine.sage.py engine.py
sage $@
# /usr/bin/time -v sage $@