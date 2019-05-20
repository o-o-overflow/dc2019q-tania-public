#!/bin/bash

set -x
set -e

# make tania
rm -f service/tania service/src/tania 
cd service/src && make
cd -
cp service/src/tania service/tania

# copy data
cp service/src/privkey service/data
cp service/src/flag service/data/flag
