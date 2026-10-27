#!/usr/bin/env python3
"""Score Ghidra's decoding (DumpSlots.java) against GNU libopcodes (slotdis, -m score7) for the
SCORE7 module and bucket every difference.

  compare.py <ghidra.txt> <objdump.txt> <corpus.bin> <le|be> <origin> [--list N] [--base ADDR]

Both inputs: "<offset-hex> <len> <text>" per slot (Ghidra "BAD", objdump "(bad)" or
"<illegal instruction>" when rejected). <origin> is the address of the first slot (0 or 2):
the class of a difference can depend on whether the slot starts at 2 mod 4.

Exact: identical text after collapsing blanks. Semantic: identical after these spellings are
normalised: objdump's "gp" is r28 and "cgp" is cr28 (objdump replaces the "r28" inside "cr28");
numbers are compared as 32-bit values, and objdump's "0x1234(4660)" / "4660(0x1234)" pairs
match either value. Other differences go to named classes; "UNEXPLAINED" must stay empty.
"""
import re
import struct
import sys
from collections import Counter, defaultdict

gpath, opath, binpath, endian, origin = sys.argv[1:6]
origin = int(origin, 0)
nlist = int(sys.argv[sys.argv.index("--list") + 1]) if "--list" in sys.argv else 5
base = int(sys.argv[sys.argv.index("--base") + 1], 0) if "--base" in sys.argv else 0
data = open(binpath, "rb").read()
fmt16 = "<H" if endian == "le" else ">H"


def load(path):
    res = {}
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        text = " ".join(p[2].split()) if len(p) > 2 else ""
        text = text.replace("<illegal instruction>", "BAD")
        if text == "(bad)":
            text = "BAD"
        res[int(p[0], 16)] = (int(p[1]), text)
    return res


def toks(text):
    text = re.sub(r"\bcgp\b", "cr28", text)
    text = re.sub(r"\bgp\b", "r28", text)
    m = text.split(" ", 1)
    mn = m[0]
    ops = m[1] if len(m) > 1 else ""
    out = [mn]
    for t in re.findall(r"-?0x[0-9a-fA-F]+\(-?[0-9]+\)|-?[0-9]+\(-?0x[0-9a-fA-F]+\)|[A-Za-z_][A-Za-z_0-9.!]*|-?0x[0-9a-fA-F]+|-?[0-9]+|\|\||[\[\]+]", ops):
        if re.match(r"^-?(0x[0-9a-fA-F]+|[0-9]+)(\(.*\))?$", t):
            vals = {int(x, 0) & 0xffffffff for x in re.findall(r"-?0x[0-9a-fA-F]+|-?[0-9]+", t)}
            out.append(("num", frozenset(vals)))
        else:
            out.append(t)
    return out


def same(g, o):
    tg, to = toks(g), toks(o)
    if len(tg) != len(to):
        return False
    for a, b in zip(tg, to):
        if isinstance(a, tuple) and isinstance(b, tuple):
            if not (a[1] & b[1]):
                return False
        elif a != b:
            return False
    return True


def half(off, k):
    """k-th halfword (program order) of the slot."""
    return struct.unpack_from(fmt16, data, off - base + 2 * k)[0]


def classify(off, g, o):
    gn, gt = g
    on, ot = o
    if gt == ot:
        return "exact"
    if gt != "BAD" and ot != "BAD" and gn == on and same(gt, ot):
        return "semantic"
    h0 = half(off, 0)
    h1 = half(off, 1) if off - base + 4 <= len(data) else 0
    upper = (origin + off) & 2
    if upper and h0 & 0x8000 and gt == "BAD":
        return "2 mod 4, marker bit set: objdump ignores the marker, Ghidra rejects (never a 16-bit instruction)"
    if not upper and endian == "le" and h0 & 0x8000 and not h1 & 0x8000:
        # LE first halfword marked, second not: objdump treats the word as a PCE pair
        return "LE marker order: objdump decodes '1,0' as PCE (gas emits PCE as '0,1'); Ghidra: parity_error"
    if not upper and endian == "le" and not h0 & 0x8000 and h1 & 0x8000:
        return "LE marker order: PCE pair ('0,1', as gas emits it); objdump decodes one 16-bit instruction"
    if not upper and endian == "be" and h0 & 0x8000 and not h1 & 0x8000 and gt == "parity_error":
        return "marker '1,0' (undefined parity, MAME exception): Ghidra parity_error, objdump decodes"
    if gt == "BAD" and " || " in ot and "BAD" in ot.split(" || "):
        return "PCE pair with a half that is not an instruction: objdump shows the other half, Ghidra rejects the pair"
    if gt.startswith("ldc3 ") and ot.startswith("ldc3 "):
        tg, to = toks(gt), toks(ot)
        if len(tg) == len(to) and tg[:-2] == to[:-2] and {v * 4 & 0xffffffff for v in to[-2][1]} & tg[-2][1]:
            return "ldc3: objdump prints the offset unscaled (ldc1/ldc2/stcN scaled by 4)"
    if gt.startswith("cmpis.c") and ot == "BAD":
        return "cmpis.c: MAME implements it, objdump 2.45 does not"
    if " || " in gt:
        ga, gb = gt.split(" || ", 1)
        oa, ob = (ot.split(" || ", 1) + [""])[:2] if " || " in ot else (ot, "")
        if ot != "BAD" and same(ga, oa) and same(gb, ob):
            return "semantic"
    return "UNEXPLAINED"


g, o = load(gpath), load(opath)
cnt = Counter()
ex = defaultdict(list)
both = 0
for off in sorted(g):
    if off not in o:
        continue
    if g[off][1] == "BAD" and o[off][1] == "BAD":
        both += 1
        continue
    c = classify(off, g[off], o[off])
    cnt[c] += 1
    if len(ex[c]) < nlist:
        ex[c].append(f"{off:08x} | {g[off][1]} | {o[off][1]}")
total = sum(cnt.values())
ok = cnt["exact"] + cnt["semantic"]
unexpl = cnt["UNEXPLAINED"]
expl = total - ok - unexpl
print(f"slots {len(g)}, decoded by either {total}: exact {cnt['exact']} ({100 * cnt['exact'] / max(total, 1):.2f}%), "
      f"semantic {ok} ({100 * ok / max(total, 1):.2f}%), explained {expl}, unexplained {unexpl}, both invalid {both}")
for c, n in cnt.most_common():
    print(f"  {n:7d}  {c}")
    for e in ex[c]:
        print("            " + e)
sys.exit(1 if unexpl else 0)
