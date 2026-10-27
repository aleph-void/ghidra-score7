#!/usr/bin/env bash
# Build the real-code samples for the SCORE7 module: freely licensed C compiled with GCC 4.5.4 for
# score-elf (the last GCC series with this target) and GNU binutils 2.20.1 (assembler and
# linker: the score linker of later releases, e.g. 2.28 and 2.45, rejects backward j/jl
# relocations as "truncated" and writes a wrong target), both byte orders. The
# sources are downloaded from pinned URLs and checked against SHA-256; nothing is committed.
#   zlib 1.3.1 (zlib license) with test/real/zmain.c (public domain) -> zlib-{le,be}.elf
#   Brad Conte's crypto-algorithms (public domain): aes, des, blowfish, md5, sha1, sha256
#     with test/real/cmain.c -> crypto-{le,be}.elf
#
#   test/build-real-samples.sh <workdir>
# Environment: SCORE_TOOLS   GCC prefix, e.g. .../bin/score-elf- (gcc)
#              SCORE_BU      binutils 2.20.1 install directory (bin/score-elf-ld, score-elf/bin/as)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${SCORE_TOOLS:?set SCORE_TOOLS to the score-elf- toolchain prefix}"
W=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$W"

fetch() { # url sha256 file
	[[ -f $3 ]] || curl -sSLf -o "$3" "$1"
	echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $3" >&2; exit 1; }
}

fetch https://zlib.net/fossils/zlib-1.3.1.tar.gz \
	9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 zlib-1.3.1.tar.gz
[[ -d zlib-1.3.1 ]] || tar xzf zlib-1.3.1.tar.gz

CA=https://raw.githubusercontent.com/B-Con/crypto-algorithms/cfbde48414baacf51fc7c74f275190881f037d32
mkdir -p crypto
while read -r f sum; do
	fetch "$CA/$f" "$sum" "crypto/$f"
done <"$HERE/real/crypto-files.txt"

mkdir -p inc
printf '#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\nvoid *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t);\nsize_t strlen(const char *);\n' >inc/string.h
cp inc/string.h inc/memory.h
printf '#include <stddef.h>\nvoid *malloc(size_t);\nvoid free(void *);\n' >inc/stdlib.h
printf '#include <stddef.h>\n' >inc/stdio.h

: "${SCORE_BU:?set SCORE_BU to a binutils 2.20.1 score-elf install}"
CC=("${SCORE_TOOLS}gcc" -B"$SCORE_BU/score-elf/bin/" -O2 -g -G 0)
LD=$SCORE_BU/bin/score-elf-ld
for e in le be; do
	EB=(-mel); LB=(-EL); [[ $e == be ]] && EB=(-meb) && LB=(-EB)
	mkdir -p "obj-$e"
	for f in adler32 compress crc32 deflate infback inffast inflate inftrees trees uncompr zutil; do
		"${CC[@]}" "${EB[@]}" -DZ_SOLO -c "zlib-1.3.1/$f.c" -o "obj-$e/z_$f.o"
	done
	"${CC[@]}" "${EB[@]}" -DZ_SOLO -Izlib-1.3.1 -c "$HERE/real/zmain.c" -o "obj-$e/zmain.o"
	"$LD" "${LB[@]}" -Ttext=0x1000 -e _start "obj-$e"/z_*.o "obj-$e/zmain.o" -o "zlib-$e.elf"
	for f in aes des blowfish md5 sha1 sha256; do
		"${CC[@]}" "${EB[@]}" -Iinc -c "crypto/$f.c" -o "obj-$e/c_$f.o"
	done
	"${CC[@]}" "${EB[@]}" -Iinc -Icrypto -c "$HERE/real/cmain.c" -o "obj-$e/cmain.o"
	"$LD" "${LB[@]}" -Ttext=0x1000 -e _start "obj-$e"/c_*.o "obj-$e/cmain.o" -o "crypto-$e.elf"
done
ls -l ./*.elf
