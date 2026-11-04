#!/bin/bash
# Machine A: run the plant + controller with snapshots and tracing until the fault occurs, then stop
# and pack everything machine B needs into $BUNDLE.
#   sudo ./demo_machine_A.sh          # real CRIU snapshots
# FAULT_AFTER=<seconds> controls when the plant injects the poison reading (default 7.9).
# Machine B must have this repo at the same absolute path (CRIU restores absolute paths and sockets).
set -e
cd "$(dirname "$0")"
make -s

RUN=${RUN:-run}
BUNDLE=${BUNDLE:-demo_bundle.tar.gz}
rm -rf "$RUN"; mkdir -p "$RUN"

./build/plant --fault-after "${FAULT_AFTER:-7.9}" </dev/null >"$RUN/plant.log" 2>&1 &
PLANT=$!
trap 'kill $PLANT 2>/dev/null || true' EXIT

rc=0
./build/supervisor --workdir "$RUN" --interval 2000 --stop-on-fault "$@" || rc=$?
[ $rc -eq 0 ] || { echo "no fault recorded (exit $rc)"; exit $rc; }

tar -czf "$BUNDLE" -C "$RUN" snap trace controller.log
[ -n "$SUDO_UID" ] && chown "$SUDO_UID:$SUDO_GID" "$BUNDLE"
echo
echo "--- controller.log (tail) ---"; tail -n 4 "$RUN/controller.log"
echo "Fault recorded. Copy $BUNDLE to machine B (same repo path) and run: sudo ./demo_machine_B.sh"
