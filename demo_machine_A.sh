#!/bin/bash
# Machine A: run the plant + controller with snapshots and tracing until the fault occurs, then stop
# and pack everything machine B needs into $BUNDLE.
#   sudo ./demo_machine_A.sh          # real CRIU snapshots
# FAULT_AFTER=<seconds> controls when the plant injects the poison reading (default 7.9).
# CRIU records absolute paths, so the controller, its log and its cwd live in a fixed $WORK dir
# that is independent of where the repo is checked out. Machine B uses the same $WORK path.
set -e
cd "$(dirname "$0")"
make -s
REPO=$PWD
WORK=${WORK:-/tmp/snapshot-rr-demo}
BUNDLE=$(realpath -m "${BUNDLE:-demo_bundle.tar.gz}")

rm -rf "$WORK"; mkdir -p "$WORK/bin"
cp build/launcher build/controller "$WORK/bin/"
cd "$WORK"

"$REPO/build/plant" --fault-after "${FAULT_AFTER:-7.9}" </dev/null >plant.log 2>&1 &
PLANT=$!
trap 'kill $PLANT 2>/dev/null || true' EXIT

rc=0
"$REPO/build/supervisor" --workdir run --launcher bin/launcher --controller bin/controller \
	--interval 2000 --stop-on-fault "$@" || rc=$?
[ $rc -eq 0 ] || { echo "no fault recorded (exit $rc)"; exit $rc; }

tar -czf "$BUNDLE" bin run/snap run/trace run/controller.log
[ -n "$SUDO_UID" ] && chown "$SUDO_UID:$SUDO_GID" "$BUNDLE"
echo
echo "--- controller.log (tail) ---"; tail -n 4 run/controller.log
echo "Fault recorded. Copy $BUNDLE to machine B and run: sudo ./demo_machine_B.sh"
