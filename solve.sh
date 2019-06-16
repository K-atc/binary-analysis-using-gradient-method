#!/bin/bash 

cd sample
make
cd - > /dev/null

sage -preparse engine.sage && mv engine.sage.py engine.py
sage solve.sage