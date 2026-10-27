# Ghidra-Rare notes: SCORE7 (Sunplus S+core7)

This is the Ghidra-Rare fork of Ghidra pull request
[#9671](https://github.com/NationalSecurityAgency/ghidra/pull/9671) (SCORE7 support by Arthur
Koba). Ghidra-Rare tested it against GNU binutils 2.45 (`objdump -m score7`), MAME's S+core core
and disassembler (BSD-3-Clause) and code compiled with GCC 4.5.4 for score-elf, and fixed what the
tests found. Authors, upstream commit and the list of changes are in [CREDITS.md](CREDITS.md);
the upstream limitations and their status are in [README.md](README.md). It targets Ghidra 12.1.4
and also builds on 12.1.3 and 12.2; prebuilt zips are on the fork's Releases page.

## What it covers

| Language ID | Description |
|---|---|
| `SCORE7:LE:32:default` | S+core7, little-endian |
| `SCORE7:BE:32:default` | S+core7, big-endian |

- Every 16-bit and 32-bit S+core7 instruction objdump decodes (special form, I-forms, J/B-forms,
  load/store with offset, pre- and post-increment, CR form with control-register, system and
  coprocessor 1-3 instructions, cache, the custom-engine group with its named operations, the
  16-bit forms including push!/pop!, the frame-pointer loads/stores and the custom-engine group),
  plus `cmpis.c` (MAME). Halfword markers as the architecture defines them: a 32-bit instruction
  has both set, a 16-bit instruction followed by a marked halfword is a PCE pair (decoded as
  both instructions, `add! r2,r3 || sub! r4,r5`), an instruction at 2 mod 4 is 16-bit, and the
  "first marked, second not" combination is the `parity_error` exception.
- Syntax: objdump's (`[ra, imm]+`, `[ra]+, imm`, byte offsets, `!` and `.c` suffixes).
- Semantics: p-code for the ALU with the V/C/Z/N/T flags (also as `cr1` through `mtcr`/`mfcr`
  and `rte`), all condition codes including `cnz` (CNT = sr0), branches, calls, returns
  (`br r3`), conditional moves and `t`, shifts and rotates (with carry), multiply/divide into
  CEH:CEL, every load/store mode, push!/pop!, PCE pairs, `abs`, `clz`. Pcodeops: see Known gaps.
- Spec files: GCC calling convention (cspec), DWARF register map, ELF opinion (e_machine 135,
  both byte orders), pspec.

## Testing

Requirements: Ghidra (`GHIDRA_INSTALL_DIR`, with this directory as `Ghidra/Processors/SCORE7`),
a GNU binutils 2.45 build with the score target (its build tree for `test/slotdis.c`, a small
libopcodes driver, and `score-elf-as`/`ld` for the emulator tests) and, for the real-code tests,
GCC 4.5.4 for score-elf with binutils 2.20.1 (see below).

```
test/run-tests.sh [workdir]          # SLEIGH compile, decode diff, every-entry test, emulator tests
test/run-tests.sh --real [workdir]   # ... plus building and analysing the real-code samples
```

The header of `test/run-tests.sh` lists the environment variables.

## Results

### Decoding vs GNU objdump 2.45

`test/gen_corpus.py` writes, per byte order, `half` (every 16-bit halfword followed by 0x0000;
65,536 slots), `w32` (every major opcode x every value of bits 14..0 with random bits 25..16 and
both markers set; 1,048,576) and `fuzz` (50,000 random words). Ghidra (`DumpSlots.java`) and
libopcodes (`slotdis`) decode each 4-byte slot at 0 mod 4 and, for `half` and `fuzz`, at 2 mod
4; `test/compare.py` scores them.

| Corpus | Decoded by either | Exact + semantic | Explained | Unexplained |
|---|---|---|---|---|
| half @0 LE / BE | 62,784 | 30,016 | 32,768 | 0 |
| w32 @0 LE / BE | 592,693 | 589,608 | 3,085 | 0 |
| fuzz @0 LE | 42,455 | 18,429 | 24,026 | 0 |
| fuzz @0 BE | 43,487 | 28,914 | 14,573 | 0 |
| half @2 LE / BE | 60,032 | 30,016 | 30,016 | 0 |
| fuzz @2 LE | 45,906 | 23,073 | 22,833 | 0 |
| fuzz @2 BE | 45,733 | 22,861 | 22,872 | 0 |

"Semantic" allows objdump's `gp` for r28 (and `cgp` for cr28), whitespace and number spellings
(objdump decimal, `0x1234(4660)` pairs). Explained classes:

| Class | Why |
|---|---|
| LE, first halfword marked and second not: objdump shows a PCE pair, Ghidra `parity_error` | objdump's little-endian disassembler has the marker order reversed: GNU as emits a PCE pair as unmarked + marked halfword in both byte orders, and MAME's disassembler and core treat "marked + unmarked" as the undefined-parity exception |
| LE, unmarked + marked halfword: Ghidra decodes a PCE pair, objdump one 16-bit instruction | same objdump bug (it does not recognise the pairs gas emits) |
| BE, marked + unmarked: Ghidra `parity_error`, objdump decodes the first halfword | undefined parity combination (MAME raises an exception) |
| BE, PCE pair with one half that is not an instruction: objdump shows the other half, Ghidra rejects the pair | a pair is only valid when both halves are |
| at 2 mod 4, halfword with the marker set: objdump decodes it with the marker ignored, Ghidra rejects | a marked halfword at 2 mod 4 is the second half of a 32-bit instruction or PCE pair, never an instruction of its own |
| `cmpis.c`: Ghidra decodes, objdump rejects | in MAME's core; missing from binutils |
| `ldc3` offset | objdump prints the `ldc3` offset unscaled but `ldc1`/`ldc2`/`stc1-3` scaled by 4 (reference-tool bug) |

MAME's `unidasm -arch score7` (little-endian only) classifies the marker combinations of the
`fuzz` corpus the same way as Ghidra: all 12,410 undefined-parity words, and every PCE pair whose
halves both decode.

**Every-entry test** (`CoverageCheck.java` over the corpora plus random fillings, 4 seeds): all
545 constructors of each language are reached; none is shadowed.

### Emulator

`test/emu_tests.py` assembles 36 short sequences with GNU as 2.45 and `EmuCheck.java` runs them
in Ghidra's emulator with hand-computed expectations (MAME's core for flags and conditions), in
both byte orders: add/sub/addc/subc/neg with carry and overflow, logic flags, bit operations,
shifts by register and immediate with carry, rotates, mul/mulu/div/divu with CEH/CEL, ldi/ldis/
ori/andi/addis/addi.c, addri/andri/orri, loads with sign/zero extension, stores in both byte
orders, pre- and post-increment, signed/unsigned compare-and-branch, `jl`/`br r3`, the `bcnz`
CNT loop, `cmpteq.c`/`mv<cond>`/`t<cond>`, `mtcr`/`mfcr cr1`, extensions, 16-bit ALU, immediate,
frame-pointer, push!/pop!, branch and high-register forms, and PCE pairs with T set and clear.
Result: 36/36 per byte order. A deliberately wrong expectation (`--break 1`) is reported.

### Real code

`test/build-real-samples.sh` downloads zlib 1.3.1 (zlib license) and Brad Conte's
crypto-algorithms (public domain) from pinned URLs with SHA-256 checks and compiles them with
GCC 4.5.4 `-O2 -g` for both byte orders, with small freestanding drivers (`test/real/*.c`,
public domain); nothing is committed. `test/real-binaries.sh` imports each ELF without
`-processor` (the opinion picks the language), analyses it, decompiles every function and
compares every instruction with objdump at the same address.

| Sample | Functions | Instructions | Bad instr. | Error bookmarks | Decompiled | Disassembly vs objdump |
|---|---|---|---|---|---|---|
| `zlib-le.elf` | 93 | 11,877 | 0 | 0 | 93 / 93 | 100% (0 unexplained) |
| `zlib-be.elf` | 93 | 11,878 | 0 | 0 | 93 / 93 | 100% |
| `crypto-le.elf` | 53 | 6,107 | 0 | 0 | 53 / 53 | 100% |
| `crypto-be.elf` | 53 | 6,106 | 0 | 0 | 53 / 53 | 100% |

DWARF from GCC is imported (function signatures and types).

## Known gaps

- **Custom-engine arithmetic without a public description** (`min`, `max`, `bitrev`, `abs.s`,
  `add.s`, `sub.s`, `sll.s`, the 22 32-bit and 12 16-bit multiply-accumulate forms, `ceinst`,
  `lcb`/`lcw`/`lce`/`scb`/`scw`/`sce`) are pcodeops that read their sources and write their
  destination (CEH:CEL for the accumulate forms): MAME does not emulate them and no non-GPL
  document describes their saturation, signedness or fractional formats.
- **System and coprocessor operations** (`syscall`, `trap`, `sdbbp`, `pflush`, `cache`, TLB
  operations, `drte`, `sleep`, `parity_error`, divide-by-zero, coprocessors 1-3) are pcodeops:
  exceptions, caches, the MMU and the coprocessors are outside the core.
- **Rotates** follow the shift instructions' carry rule (C = last bit rotated out; `rorc`/`rolc`
  rotate through C); MAME does not emulate them, so this is unverified.
- **Ghidra's SLEIGH assembler** throws a NullPointerException for this language on Ghidra
  12.1.4 (the decode rule uses `inst_start`); the pull request's fix to
  `StartInstructionValueSolver` is a change to Ghidra itself. Disassembly, decompilation and
  emulation are not affected.
- **ELF relocations** are not applied (linked executables have none; object files would keep
  unrelocated `j`/`jl`/`la` targets).

## Unverified

- No freely licensed S+core7 firmware or binaries from other compilers were found; real-code
  tests use GCC 4.5.4 output.
- Hardware behaviour of rotates (flags), PCE when T changes inside the pair, and the custom
  engine.

## Confirmed reference-tool bugs

- binutils 2.45 `objdump -m score7`, little-endian: PCE marker order reversed (see the table);
  `ldc3` offset printed unscaled.
- binutils 2.28 and 2.45 `ld` (score-elf): backward `j`/`jl` (`R_SCORE_24`) are reported as
  "relocation truncated to fit" and written with a wrong target; binutils 2.20.1 links them
  correctly, so the samples are assembled and linked with 2.20.1.
- GCC 4.5.4 for score-elf: building libgcc's floating-point helpers ICEs (`cselib_record_set`);
  the samples need no libgcc. GCC selects the byte order with `-mel`/`-meb` (not `-EL`/`-EB`).
