#!/bin/bash
# One-shot demo of: run -> snapshots -> fault -> suspend -> restore -> replay -> fault again.
#   sudo ./demo.sh               # real CRIU snapshots
#   ./demo.sh --no-criu          # no root needed; replay restarts the controller from scratch
# FAULT_AFTER=<seconds> controls when the plant injects the poison reading (default 7).
set -e
cd "$(dirname "$0")"
make -s

RUN=${RUN:-run}
rm -rf "$RUN"; mkdir -p "$RUN"

./build/plant --fault-after "${FAULT_AFTER:-7}" </dev/null >"$RUN/plant.log" 2>&1 &
PLANT=$!
trap 'kill $PLANT 2>/dev/null || true' EXIT

# Replay is hands-off: the supervisor stops the plant itself (--plant-pid) before restoring.
rc=0
./build/supervisor --workdir "$RUN" --interval 1000 --plant-pid "$PLANT" --auto-replay "$@" || rc=$?

echo
echo "--- plant.log (tail) ---";      tail -n 4 "$RUN/plant.log"
echo "--- controller.log (tail) ---"; tail -n 6 "$RUN/controller.log"
echo "supervisor exit code: $rc (0 = fault reproduced from the trace)"
exit $rc
