#!/bin/bash 

if [ $# -ne 1 ]; then
    echo "usage: $0 SOLVER_SAGE_FILE"
    exit
fi

SOLVER_SAGE_FILE=$1

cd sample
make
cd - > /dev/null

sage -preparse engine.sage && mv engine.sage.py engine.py
sage $SOLVER_SAGE_FILE