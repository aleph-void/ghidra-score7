#!/usr/bin/env python3
"""Decode-test corpora for the SCORE7 module, 4-byte slots, written in both byte orders.

  gen_corpus.py <outdir>
  -> half_{le,be}.bin   every 16-bit halfword as the first halfword of a slot, followed by 0x0000
                        (bit 15 clear: a 16-bit instruction; set: the parity-bit combinations
                        "10"/"01" of a 32-bit packet)
     w32_{le,be}.bin    every 32-bit instruction: for each major opcode (bits 30..26) every value
                        of bits 14..0, with random bits 25..16 and both parity bits set
     fuzz_{le,be}.bin   50,000 random 32-bit words
Decode them at address 0 (the slots start at 0 mod 4) and, imported at address 2, at 2 mod 4,
where the architecture decodes a 16-bit instruction from the first halfword whatever follows.

A 32-bit instruction is a 32-bit word in the byte order of the target (bit 15 and bit 31 are
the parity bits); a 16-bit instruction is a halfword. The encodings are generated from the field
layout alone; nothing is taken from binutils.
"""
import os
import random
import struct
import sys

out = sys.argv[1]
R = random.Random(20261027)


def save(name, words):
    for e, fmt in (("le", "<I"), ("be", ">I")):
        with open(os.path.join(out, f"{name}_{e}.bin"), "wb") as f:
            for w in words:
                f.write(struct.pack(fmt, w))


def save_half(name, halves):
    # a halfword followed by 0x0000, in the target byte order
    for e, fmt in (("le", "<HH"), ("be", ">HH")):
        with open(os.path.join(out, f"{name}_{e}.bin"), "wb") as f:
            for h in halves:
                f.write(struct.pack(fmt, h, 0))


save_half("half", range(0x10000))
w32 = []
for major in range(32):
    for low in range(0x8000):
        w32.append(0x80008000 | (major << 26) | (R.getrandbits(10) << 16) | low)
save("w32", w32)
save("fuzz", [R.getrandbits(32) for _ in range(50000)])
print(0x10000, len(w32), 50000)
