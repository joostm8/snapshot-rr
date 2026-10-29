#!/bin/bash
# Compare control-loop timing without tracing, with tracing, and with tracing + CRIU snapshots.
# All timings come from the controller's own clock (see [stat]/[late] lines in its log).
#   ./bench.sh            # untraced and traced (no root needed)
#   sudo ./bench.sh       # also traced + snapshots
# SECS=<n> sets the duration of each scenario (default 20).
cd "$(dirname "$0")"
make -s || exit 1
SECS=${SECS:-20}
OUT=run-bench
rm -rf "$OUT"; mkdir -p "$OUT"

summarize() { # <label> <controller log>
	awk -v label="$1" '
	/^\[stat\]/ { if (++n == 1) next
		for (i = 2; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] }
		w++; wa += v["wake_avg"]; pa += v["proc_avg"]
		if (v["wake_max"] > wm) wm = v["wake_max"]; if (v["proc_max"] > pm) pm = v["proc_max"]
		miss += v["missed"] }
	/^\[late\]/ { late++ }
	END { if (w) printf "%-28s %10.0f %10.0f %10.0f %10.0f %8d %6d\n", label, wa/w, wm, pa/w, pm, miss, late
	      else printf "%-28s (no data)\n", label }' "$2"
}

run_plant() { ./build/plant </dev/null >/dev/null 2>&1 & PLANT=$!; }
stop_all() { kill "$PLANT" 2>/dev/null; wait "$PLANT" 2>/dev/null; }

printf "%-28s %10s %10s %10s %10s %8s %6s\n" scenario "wake avg" "wake max" "work avg" "work max" "missed" "late"
printf "%-28s %10s %10s %10s %10s %8s %6s\n" "" "(us)" "(us)" "(us)" "(us)" "ticks" "ticks"

# A: controller run directly, no filter, no tracer
run_plant
./build/controller "$OUT/none.sock" 2>"$OUT/A.log" & CTRL=$!
sleep "$SECS"; kill "$CTRL"; wait "$CTRL" 2>/dev/null; stop_all
summarize "A untraced" "$OUT/A.log"

# B: seccomp filter + ptrace recording, no snapshots
run_plant
./build/supervisor --workdir "$OUT/B" --no-criu >/dev/null & SUP=$!
sleep "$SECS"; kill -INT "$SUP"; wait "$SUP" 2>/dev/null; stop_all
summarize "B traced" "$OUT/B/controller.log"

# C: traced + a CRIU snapshot every second
if [ "$(id -u)" -eq 0 ]; then
	run_plant
	./build/supervisor --workdir "$OUT/C" --interval 1000 >"$OUT/C.sup" & SUP=$!
	sleep "$SECS"; kill -INT "$SUP"; wait "$SUP" 2>/dev/null; stop_all
	summarize "C traced + snapshot/1s" "$OUT/C/controller.log"
	echo; grep -E "^(tracing|snapshots|late ticks)" "$OUT/C.sup"
else
	echo "C traced + snapshots         (skipped: needs root)"
fi
echo
echo "wake = timer expiry -> controller running; work = per-tick processing incl. tracing stalls."
