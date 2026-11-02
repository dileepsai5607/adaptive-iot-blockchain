#!/bin/bash
cd "$(dirname "$0")/.."
stopall() { for p in $(ps -eo pid,comm | awk '$2=="java"{print $1}'); do kill -9 $p; done; pkill -x ipfs; sleep 4; rm -rf run/*; }
stopall
for k in 1 2 3; do
  echo "[$(date +%T)] besu rep $k"
  CHAIN=besu VALIDATORS=4 RATE=10 N_WRITE=600 N_ASYNC=1000 RETH_OUT=reps/e2_e4_besu_r$k.json RETH_PORT=$((8675 + k)) python3 bench/bench_reth.py 2>&1 | grep -vE "^\s*$" | tail -14
  stopall
done
echo "[$(date +%T)] BESU DONE"
