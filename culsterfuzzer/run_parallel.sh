#!/usr/bin/env bash
# run_parallel.sh
# Usage:
#   ./run_parallel.sh [CONCURRENCY] [TOTAL_ITERATIONS]
# Example:
#   ./run_parallel.sh 40 2000
#
# Behavior:
# - Spawns CONCURRENCY workers, each runs pdf_mutator_upload.py with ITERATIONS = ceil(TOTAL_ITERATIONS/CONCURRENCY)
# - Writes per-worker logs to logs/worker_<n>.log
# - Provides a simple monitor that prints aggregated counts every 3s:
#     - number of lines reporting status=201, 401, 5xx, ERR (no status)
#     - number of saved crash files in reports/crashes
#
# Notes:
# - Ensure python3 and pdf_mutator_upload.py are runnable in this directory.
# - Adjust TIMEOUT/ITERATIONS inside pdf_mutator_upload.py for heavier loads if needed.

set -euo pipefail

CONCURRENCY="${1:-20}"
TOTAL_ITERATIONS="${2:-1000}"

# compute iterations per worker (ceil)
ITER_PER_WORKER=$(( (TOTAL_ITERATIONS + CONCURRENCY - 1) / CONCURRENCY ))

LOGDIR="logs"
mkdir -p "$LOGDIR"
mkdir -p reports/crashes

echo "[*] Starting fuzz run: concurrency=$CONCURRENCY total_iterations=$TOTAL_ITERATIONS (each worker: $ITER_PER_WORKER)"
echo "[*] Logs -> $LOGDIR/worker_*.log"
echo

# export ITERATIONS override for workers (pdf_mutator_upload.py reads ITERATIONS constant; we pass via env override)
# We'll run each worker in its own env to override ITERATIONS/TIMEOUT if needed.
WORK_PIDS=()
for i in $(seq 1 "$CONCURRENCY"); do
  LOGFILE="$LOGDIR/worker_${i}.log"
  # start worker in background; override ITERATIONS and optionally TIMEOUT via env
  ( 
    echo "[`date -u +%Y-%m-%dT%H:%M:%SZ`] Worker $i starting, iterations=$ITER_PER_WORKER"
    # Export ITERATIONS env var so script can pick it if implemented to read env (if not, script's constant still applies)
    ITERATIONS="$ITER_PER_WORKER" TIMEOUT=30 python3 pdf_mutator_upload.py 2>&1 | sed "s/^/W${i} | /" >> "$LOGFILE"
    echo "[`date -u +%Y-%m-%dT%H:%M:%SZ`] Worker $i finished"
  ) &
  WORK_PIDS+=($!)
  sleep 0.05
done

# Monitor loop: aggregate counts from logs
echo "[*] Launched ${#WORK_PIDS[@]} workers, pids: ${WORK_PIDS[*]}"
echo

monitor_interval=3
start_ts=$(date +%s)
while true; do
  # If all pids exited, break
  all_done=true
  for pid in "${WORK_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      all_done=false
      break
    fi
  done

  # aggregate stats
  total_lines=$(cat logs/worker_*.log 2>/dev/null | wc -l || echo 0)
  c201=$(grep -h "status=201" logs/worker_*.log 2>/dev/null | wc -l || echo 0)
  c401=$(grep -h "status=401" logs/worker_*.log 2>/dev/null | wc -l || echo 0)
  c5xx=$(grep -h -E "status=5[0-9][0-9]" logs/worker_*.log 2>/dev/null | wc -l || echo 0)
  cerr=$(grep -h "status=None" logs/worker_*.log 2>/dev/null | wc -l || echo 0)
  crashes_saved=$(ls -1 reports/crashes/crash_*.pdf 2>/dev/null | wc -l || echo 0)

  now_ts=$(date +%s)
  elapsed=$((now_ts - start_ts))
  printf "\r[+ %4ds] lines=%6s 201=%5s 401=%5s 5xx=%5s none=%5s saved=%4s" \
    "$elapsed" "$total_lines" "$c201" "$c401" "$c5xx" "$cerr" "$crashes_saved"

  if $all_done; then
    echo
    echo "[*] All workers finished."
    break
  fi

  sleep "$monitor_interval"
done

# Print tail of logs for quick inspection
echo
echo "=== Last 20 lines from each worker log ==="
for f in logs/worker_*.log; do
  echo "---- $f ----"
  tail -n 20 "$f" || true
done

echo
echo "[*] Final counts:"
echo "  total log lines: $total_lines"
echo "  status=201: $c201"
echo "  status=401: $c401"
echo "  status=5xx: $c5xx"
echo "  status=None (request exception): $cerr"
echo "  crash samples saved: $crashes_saved"

echo "[*] Done."
