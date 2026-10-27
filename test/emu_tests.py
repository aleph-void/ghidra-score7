#!/usr/bin/env python3
"""P-code semantic tests for Ghidra's emulator (EmuCheck.java), assembled with GNU as for
score-elf (binutils 2.45).

  emu_tests.py <outdir> <bin-prefix> [--break N]
      <bin-prefix>: binutils prefix, e.g. .../bin/score-elf- (needs as, ld, objcopy, nm)
  -> emu_{le,be}.bin and emu_{le,be}.txt

Each test is a short sequence at its own 0x100-aligned address followed by a "stop" label. The
.txt files have one line per test:
  <name> <start-hex> <stop-hex> <init: reg=val,...|-> <expect: reg=val,...>
Values are hex. A data area at 0x8000 (D0 below) is part of the image. The expected values are
worked out by hand from the instruction descriptions (MAME's BSD-licensed SCORE7 core for the
flags and the CNT condition); they are not taken from the module's output.
--break N makes the expectation of test N wrong (to show that the check can fail).
"""
import os
import re
import subprocess
import sys

out, pre = sys.argv[1], sys.argv[2]
brk = int(sys.argv[sys.argv.index("--break") + 1]) if "--break" in sys.argv else -1
M = 0xffffffff

# data area at 0x8000: 16 bytes 00 01 02 ... 0f, then 0x80 0xff 0x7f 0x00, then zeros
D0 = bytes(range(16)) + bytes([0x80, 0xff, 0x7f, 0x00]) + bytes(44)


def word(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 4]
    return int.from_bytes(b, "little" if e == "le" else "big")


def half(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 2]
    return int.from_bytes(b, "little" if e == "le" else "big")


# (name, asm, init, expect); expect may be a function of the byte order
T = [
    ("add.c_carry", "add.c r4, r5, r6", {"r5": M, "r6": 1}, {"r4": 0, "Z": 1, "N": 0, "C": 1, "V": 0}),
    ("add.c_overflow", "add.c r4, r5, r6", {"r5": 0x7fffffff, "r6": 1},
     {"r4": 0x80000000, "Z": 0, "N": 1, "C": 0, "V": 1}),
    ("add_no_flags", "add r4, r5, r6", {"r5": M, "r6": 1, "Z": 0, "C": 0}, {"r4": 0, "Z": 0, "C": 0}),
    ("sub.c_borrow", "sub.c r4, r5, r6", {"r5": 1, "r6": 2}, {"r4": M, "Z": 0, "N": 1, "C": 0, "V": 0}),
    ("sub.c_no_borrow", "sub.c r4, r5, r6", {"r5": 5, "r6": 5}, {"r4": 0, "Z": 1, "N": 0, "C": 1, "V": 0}),
    ("subc_carry_clear", "subc r4, r5, r6", {"r5": 10, "r6": 3, "C": 0}, {"r4": 6}),
    ("addc.c_carry_in", "addc.c r4, r5, r6", {"r5": M, "r6": 0, "C": 1}, {"r4": 0, "C": 1, "Z": 1}),
    ("neg.c", "neg.c r4, r5", {"r5": 1}, {"r4": M, "N": 1, "C": 0, "Z": 0}),
    ("logic_c", "and.c r4, r5, r6\n or r7, r5, r6\n xor r8, r5, r6\n not.c r9, r5",
     {"r5": 0xf0f0, "r6": 0xff00}, {"r4": 0xf000, "r7": 0xfff0, "r8": 0x0ff0, "r9": 0xffff0f0f, "N": 1, "Z": 0}),
    ("bit_ops", "bitset.c r4, r5, 4\n bitclr.c r6, r5, 0\n bittgl.c r7, r5, 31\n bittst.c r5, 1",
     {"r5": 0x1}, {"r4": 0x11, "r6": 0, "r7": 0x80000001, "Z": 1, "N": 0}),
    ("shift_reg_c", "sll.c r4, r5, r6\n srl r7, r5, r6", {"r5": 0xc0000001, "r6": 1},
     {"r4": 0x80000002, "C": 1, "N": 1, "r7": 0x60000000}),
    ("shift_imm", "slli r4, r5, 4\n srli r6, r5, 4\n srai.c r7, r5, 4", {"r5": 0x80000018},
     {"r4": 0x180, "r6": 0x08000001, "r7": 0xf8000001, "C": 1, "N": 1}),
    ("rotate", "ror r4, r5, r6\n rol r7, r5, r6\n roli r8, r5, 8", {"r5": 0x12345678, "r6": 4},
     {"r4": 0x81234567, "r7": 0x23456781, "r8": 0x34567812}),
    ("mul_div", "mul r5, r6\n mfcel r7\n mfceh r8\n divu r9, r10\n mfcel r11\n mfceh r12",
     {"r5": M, "r6": 2, "r9": 17, "r10": 5}, {"r7": 0xfffffffe, "r8": M, "r11": 3, "r12": 2}),
    ("mulu_div_signed", "mulu r5, r6\n mfceh r7\n div r8, r9\n mfcel r10\n mfceh r11",
     {"r5": M, "r6": 2, "r8": (-17) & M, "r9": 5}, {"r7": 1, "r10": (-3) & M, "r11": (-2) & M}),
    ("immediates", "ldi r4, -2\n ldis r5, 0x1234\n ori r5, 0x5678\n addis r6, 1\n andi r7, 0xff00\n addi.c r8, -1",
     {"r6": 5, "r7": 0x12345678, "r8": 1},
     {"r4": 0xfffffffe, "r5": 0x12345678, "r6": 0x10005, "r7": 0x5600, "r8": 0, "Z": 1, "C": 1}),
    ("ri_form", "addri r4, r5, -16\n andri r6, r5, 0x3ff0\n orri.c r7, r5, 1", {"r5": 0x80001234},
     {"r4": 0x80001224, "r6": 0x1230, "r7": 0x80001235, "N": 1}),
    ("loads", "ldis r5, 0\n ori r5, 0x8000\n lw r4, [r5, 4]\n lh r6, [r5, 16]\n lhu r7, [r5, 16]\n"
     " lb r8, [r5, 16]\n lbu r9, [r5, 17]", {},
     lambda e: {"r4": word(0x8004, e), "r6": half(0x8010, e) | (0xffff0000 if half(0x8010, e) & 0x8000 else 0),
                "r7": half(0x8010, e), "r8": 0xffffff80, "r9": 0xff}),
    ("stores", "ldis r5, 0\n ori r5, 0x8020\n sw r6, [r5, 0]\n sh r6, [r5, 4]\n sb r6, [r5, 8]\n"
     " lw r7, [r5, 0]\n lw r8, [r5, 4]\n lw r9, [r5, 8]", {"r6": 0xaabbccdd},
     lambda e: {"r7": 0xaabbccdd, "r8": 0xccdd0000 if e == "be" else 0xccdd, "r9": 0xdd000000 if e == "be" else 0xdd}),
    ("pre_post_increment", "ldis r5, 0\n ori r5, 0x8000\n lw r4, [r5, 4]+\n lw r6, [r5]+, 8\n sw r7, [r5, -4]+",
     {"r7": 0x55}, lambda e: {"r4": word(0x8004, e), "r6": word(0x8004, e), "r5": 0x8008}),
    ("cmp_branch", "cmp.c r5, r6\n bgtu 1f\n ldi r4, 1\n b 2f\n1: ldi r4, 2\n2: nop", {"r5": 5, "r6": 3},
     {"r4": 2, "C": 1, "Z": 0}),
    ("cmp_branch_signed", "cmp.c r5, r6\n bgt 1f\n ldi r4, 1\n b 2f\n1: ldi r4, 2\n2: nop",
     {"r5": M, "r6": 3}, {"r4": 1, "N": 1}),
    ("call_return", "jl 1f\n ldi r4, 7\n b 2f\n1: ldi r5, 9\n br r3\n2: nop", {}, {"r4": 7, "r5": 9}),
    ("cnt_loop", "ldi r4, 0\n1: addi r4, 1\n bcnz 1b", {"sr0": 3}, {"r4": 4, "sr0": 0}),
    ("t_and_mv", "cmpteq.c r5, r6\n mvcs r7, r8\n mveq r9, r8\n tcs", {"r5": 2, "r6": 2, "r8": 0x77},
     {"T": 1, "r7": 0x77, "r9": 0x77, "C": 1}),
    ("cr1_flags", "mtcr r5, cr1\n mfcr r6, cr1", {"r5": 0x15}, {"V": 1, "C": 0, "Z": 1, "N": 0, "T": 1, "r6": 0x15}),
    ("extend", "extsb r4, r5\n extzh r6, r5\n extsh.c r7, r5", {"r5": 0x1234f080},
     {"r4": 0xffffff80, "r6": 0xf080, "r7": 0xfffff080, "N": 1}),
    ("compact_alu", "add! r4, r5\n sub! r6, r5\n mv! r7, r4\n ldiu! r8, 200\n cmp! r6, r6",
     {"r4": 1, "r5": 2, "r6": 10}, {"r4": 3, "r6": 8, "r7": 3, "r8": 200, "Z": 1, "C": 1}),
    ("compact_imm", "addei! r4, 3\n subei! r5, 2\n slli! r6, 1\n srli! r7, 1", {"r4": 1, "r5": 10, "r6": 0x80000001, "r7": 3},
     {"r4": 9, "r5": 6, "r6": 2, "r7": 1, "C": 1}),
    ("frame_access", "ldis r2, 0\n ori r2, 0x8000\n lwp! r4, 4\n lhp! r5, 16\n lbup! r6, 17\n swp! r7, 40\n lw r8, [r2, 40]",
     {"r7": 0x1234}, lambda e: {"r4": word(0x8004, e),
                                "r5": half(0x8010, e) | (0xffff0000 if half(0x8010, e) & 0x8000 else 0),
                                "r6": 0xff, "r8": 0x1234}),
    ("push_pop", "ldis r0, 0\n ori r0, 0x8040\n push! r5, [r0]\n push! r16, [r0]\n pop! r6, [r0]\n pop! r7, [r0]",
     {"r5": 0x11, "r16": 0x22}, {"r6": 0x22, "r7": 0x11, "r0": 0x8040}),
    ("compact_branch", "ldiu! r4, 0\n1: addei! r4, 0\n cmp! r4, r5\n bne! 1b", {"r5": 5}, {"r4": 5, "Z": 1}),
    ("mlfh_mhfl", "mlfh! r4, r17\n mhfl! r18, r5", {"r17": 0x99, "r5": 0x44}, {"r4": 0x99, "r18": 0x44}),
    ("pce_t_set", "tset\n add! r4, r5 || sub! r6, r5", {"r4": 1, "r5": 2, "r6": 10}, {"r4": 3, "r6": 10}),
    ("pce_t_clear", "cmpteq.c r5, r6\n add! r4, r5 || sub! r6, r5", {"r4": 1, "r5": 2, "r6": 10},
     {"r4": 1, "r6": 8}),
    ("cnt_condition_t", "tcnz", {"sr0": 2}, {"T": 1, "sr0": 2}),
]


def build(e):
    src = [" .text"]
    for i, (name, asm, _, _) in enumerate(T):
        src.append(f" .org {i * 0x100:#x}\nT{i}: {asm}\nS{i}: nop\n")
    src.append(" .org 0x8000\n .byte " + ",".join(str(b) for b in D0))
    base = f"{out}/emu_{e}"
    open(base + ".s", "w").write("\n".join(src) + "\n")
    eb = ["-EB"] if e == "be" else ["-EL"]
    subprocess.run([pre + "as"] + eb + [base + ".s", "-o", base + ".o"], check=True,
                   stderr=subprocess.DEVNULL)
    subprocess.run([pre + "ld"] + eb + ["-Ttext=0", "-e", "0", base + ".o", "-o", base + ".elf"], check=True)
    subprocess.run([pre + "objcopy", "-O", "binary", "-j", ".text", base + ".elf", base + ".bin"], check=True)
    syms = {}
    for line in subprocess.run([pre + "nm", base + ".elf"], capture_output=True, text=True).stdout.split("\n"):
        m = re.match(r"([0-9a-f]+) \w (\w+)$", line)
        if m:
            syms[m.group(2)] = int(m.group(1), 16)
    with open(base + ".txt", "w") as f:
        for i, (name, _, init, exp) in enumerate(T):
            exp = exp(e) if callable(exp) else dict(exp)
            if i == brk:
                r = next(iter(exp))
                exp[r] ^= 1
            ini = ",".join(f"{r}={v & M:x}" for r, v in init.items()) or "-"
            f.write(f"{name} {syms['T%d' % i]:x} {syms['S%d' % i]:x} {ini} "
                    + ",".join(f"{r}={v & M:x}" for r, v in exp.items()) + "\n")
    for x in (".o", ".elf"):
        os.remove(base + x)


for e in ("le", "be"):
    build(e)
print(f"{len(T)} tests")
