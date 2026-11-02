#!/bin/bash
# Sequential re-run of remaining experiments with cleanup between stages.
cd "$(dirname "$0")/.."
log=results/reps/run_all_v2.log
echo "---- restart $(date +%T)" >> $log
clean() { pkill -x anvil; pkill -x reth; pkill -x ipfs; pkill -f "besu-25.10.0"; sleep 3; rm -rf run/* /root/.foundry/anvil/tmp; }
clean
echo "[$(date +%T)] security+gas" >> $log
python3 bench/bench_security_gas.py >> $log 2>&1; clean
echo "[$(date +%T)] policy" >> $log
python3 bench/bench_policy.py >> $log 2>&1; clean
for k in 1 2 3; do
  echo "[$(date +%T)] reth rep $k" >> $log
  RETH_OUT=reps/e2_e4_reth_r$k.json RETH_PORT=$((8575 + k)) python3 bench/bench_reth.py >> $log 2>&1; clean
done
echo "[$(date +%T)] ALL DONE" >> $log
