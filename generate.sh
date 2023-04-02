#!/usr/bin/env bash

set -x
set -e

mkdir -p cnfs

for bytes in {4..13}
do
  for missing in {1..2}
  do
    ./generate_formulas.py -n $bytes -m $missing
    rm asconhashv12_opt64_*.c
    f=$(ls asconhashv12_opt64*.cnf)
    f=$(basename $f)
    grep -v "^c" $f > cnfs/$f
    rm $f
  done
done