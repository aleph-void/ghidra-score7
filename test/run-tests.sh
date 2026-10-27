#!/usr/bin/env bash
# SCORE7 module tests:
#   1. both .slaspec files compile
#   2. decode corpora (test/gen_corpus.py: every 16-bit halfword, every 32-bit major opcode x
#      bits 14..0, 50,000 random words; at 0 mod 4 and at 2 mod 4) vs GNU libopcodes
#      (-m score7), both byte orders
#   3. every-entry decode test (CoverageCheck.java over the corpora, 4 seeds, union)
#   4. p-code emulator tests (EmuCheck.java, both byte orders) and a deliberately broken
#      expectation that must fail
#   5. with --real: build the real-code samples (test/build-real-samples.sh) and run
#      test/real-binaries.sh on them
#
#   test/run-tests.sh [--real] [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x/12.2 whose Ghidra/Processors/SCORE7 is (a symlink to) this
#                       module directory
#   SLOTDIS             binary built from test/slotdis.c against libopcodes of a binutils build
#                       with the score target (or BU_BUILD = that build tree and BU_SRC = its source)
#   SCORE_BU_NEW        binutils (2.45) prefix for the emulator tests, e.g. .../bin/score-elf-
#   SCORE_TOOLS, SCORE_BU   (--real) GCC 4.5.4 prefix and binutils 2.20.1 install, see
#                       test/build-real-samples.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
source "$HERE/env.sh"
REAL=0
if [[ ${1:-} == --real ]]; then REAL=1; shift; fi
: "${SCORE_BU_NEW:?set SCORE_BU_NEW}"
W=$(mkdir -p "${1:-score7-test-work}" && cd "${1:-score7-test-work}" && pwd)
cd "$W"
rc=0

echo "== compiling SLEIGH"
for s in "$MOD"/data/languages/*.slaspec; do
	if "$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "ERROR|^Error"; then
		echo "FAIL: $s does not compile"; exit 1
	fi
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_BUILD:?set SLOTDIS, or BU_BUILD and BU_SRC}" "${BU_SRC:?set BU_SRC}"
	SLOTDIS=$W/slotdis
	gcc -O2 -w -DPACKAGE=1 -DPACKAGE_VERSION=1 -o "$SLOTDIS" "$HERE/slotdis.c" -I"$BU_BUILD/bfd" \
		-I"$BU_SRC/include" "$BU_BUILD/opcodes/.libs/libopcodes.a" "$BU_BUILD/bfd/.libs/libbfd.a" \
		"$BU_BUILD/libsframe/.libs/libsframe.a" "$BU_BUILD/libiberty/libiberty.a" -lz -lzstd
fi
export SLOTDIS

echo "== decode corpora vs GNU libopcodes (-m score7)"
python3 "$HERE/gen_corpus.py" .
"$HERE/decode-diff.sh" . || rc=1

echo "== every-entry decode test"
for l in LE BE; do
	e=${l,,}
	cat half_$e.bin w32_$e.bin fuzz_$e.bin >cov_$e.bin
	for seed in 1 2 3 4; do
		"$HERE/ghidra-script.sh" raw SCORE7:$l:32:default cov_$e.bin CoverageCheck.java "$W/cov_${l}_$seed.txt" 2048 $seed 4 &
	done
	wait
	tot=$(grep -h '^coverage' cov_${l}_1.txt | sed 's/coverage: \([0-9]*\) constructors.*/\1/')
	un=$(cat cov_${l}_*.txt | { grep '^unreached' || true; } | sort | uniq -c | awk '$1==4' | wc -l)
	echo "-- SCORE7:$l:32:default: $tot constructors, $((tot - un)) reached by at least one of 4 seeds"
	cat cov_${l}_*.txt | { grep '^unreached' || true; } | sort | uniq -c | awk '$1==4 {print "   " $0}'
	(( un == 0 )) || rc=1
done

echo "== p-code emulator tests"
mkdir -p emu emu_broken
python3 "$HERE/emu_tests.py" emu "$SCORE_BU_NEW"
python3 "$HERE/emu_tests.py" emu_broken "$SCORE_BU_NEW" --break 1 >/dev/null
for e in le be; do
	"$HERE/ghidra-script.sh" raw "SCORE7:${e^^}:32:default" emu/emu_$e.bin EmuCheck.java \
		"$W/emu/emu_$e.txt" "$W/emu/res_$e.txt" &
done
wait
for e in le be; do
	echo "-- $e: $(tail -n 1 emu/res_$e.txt)"
	if grep -v "^PASS\|^emulator" emu/res_$e.txt; then rc=1; fi
done
"$HERE/ghidra-script.sh" raw SCORE7:LE:32:default emu_broken/emu_le.bin EmuCheck.java \
	"$W/emu_broken/emu_le.txt" "$W/emu_broken/res.txt"
if grep -q '^FAIL' emu_broken/res.txt; then
	echo "-- deliberately wrong expectation: $(grep '^FAIL' emu_broken/res.txt)"
else
	echo "FAIL: deliberately wrong expectation NOT DETECTED"; rc=1
fi

if (( REAL )); then
	echo "== real binaries"
	"$HERE/build-real-samples.sh" "$W/samples"
	"$HERE/real-binaries.sh" "$W/samples" "$W/real" || rc=1
fi
echo "== done: $([[ $rc == 0 ]] && echo PASS || echo FAIL)"
exit $rc
