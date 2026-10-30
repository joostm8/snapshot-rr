#!/bin/bash
# Machine B: restore the newest snapshot from the bundle made by demo_machine_A.sh and replay the
# recorded trace, without any plant, to reproduce the fault.
#   sudo ./demo_machine_B.sh [bundle.tar.gz]
# The repo must be at the same absolute path as on machine A.
set -e
cd "$(dirname "$0")"
make -s

RUN=${RUN:-run}
BUNDLE=${1:-${BUNDLE:-demo_bundle.tar.gz}}
[ -f "$BUNDLE" ] || { echo "bundle $BUNDLE not found"; exit 1; }
rm -rf "$RUN"; mkdir -p "$RUN"
tar -xzf "$BUNDLE" -C "$RUN"

rc=0
./build/supervisor --workdir "$RUN" --replay-only "${@:2}" || rc=$?

echo "--- controller.log (tail) ---"; tail -n 6 "$RUN/controller.log"
echo "supervisor exit code: $rc (0 = fault reproduced from the trace)"
exit $rc
