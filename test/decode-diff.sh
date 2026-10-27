#!/usr/bin/env bash
# Decode the corpora (gen_corpus.py) with Ghidra and with GNU libopcodes (-m score7) and compare,
# both byte orders, with the slots at 0 mod 4 (origin 0) and at 2 mod 4 (origin 2).
#   test/decode-diff.sh <workdir>
# Environment: GHIDRA_INSTALL_DIR, SLOTDIS (slotdis binary built from test/slotdis.c)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
W=$(readlink -f "$1")
cd "$W"
rc=0
RUNS="half:0 w32:0 fuzz:0 half:2 fuzz:2"
for e in le be; do
	L=SCORE7:${e^^}:32:default
	eb=little; [[ $e == be ]] && eb=big
	pids=()
	for r in $RUNS; do
		c=${r%:*} org=${r#*:}
		BASE=$org "$HERE/ghidra-slots.sh" "$L" ${c}_$e.bin 4 g_${c}${org}_$e.txt 2>/dev/null &
		pids+=($!)
	done
	for p in "${pids[@]}"; do wait "$p" || rc=1; done
	for r in $RUNS; do
		c=${r%:*} org=${r#*:}
		"$SLOTDIS" score:score7 4 ${c}_$e.bin -e $eb -o $org >o_${c}${org}_$e.txt
		python3 "$HERE/compare.py" g_${c}${org}_$e.txt o_${c}${org}_$e.txt ${c}_$e.bin $e $org >cmp_${c}${org}_$e.txt || rc=1
		echo "-- $c@$org $e: $(head -1 cmp_${c}${org}_$e.txt)"
	done
done
exit $rc
