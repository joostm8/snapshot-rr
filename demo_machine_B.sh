#!/bin/bash
# Machine B: restore the newest snapshot from the bundle made by demo_machine_A.sh and replay the
# recorded trace, without any plant, to reproduce the fault.
#   sudo ./demo_machine_B.sh [bundle.tar.gz]
# Needs the same $WORK path as machine A (default /tmp/snapshot-rr-demo); the repo can be anywhere.
set -e
cd "$(dirname "$0")"
make -s
REPO=$PWD
WORK=${WORK:-/tmp/snapshot-rr-demo}
BUNDLE=$(realpath -m "${1:-${BUNDLE:-demo_bundle.tar.gz}}")
[ -f "$BUNDLE" ] || { echo "bundle $BUNDLE not found"; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"
tar -xzf "$BUNDLE" -C "$WORK"
cd "$WORK"

rc=0
"$REPO/build/supervisor" --workdir run --launcher bin/launcher --controller bin/controller \
	--replay-only "${@:2}" || rc=$?

echo "--- controller.log (tail) ---"; tail -n 6 run/controller.log
echo "supervisor exit code: $rc (0 = fault reproduced from the trace)"
exit $rc
