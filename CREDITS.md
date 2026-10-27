# Credits: SCORE7 (Sunplus S+core7) module

This module is a community SLEIGH module that Ghidra-Rare imported, tested and fixed. The
original processor specification was written by Arthur Koba as a Ghidra pull request.
Ghidra-Rare's changes are listed below.

## Upstream

| | |
|---|---|
| Source | Ghidra pull request [#9671](https://github.com/NationalSecurityAgency/ghidra/pull/9671) "Add SCORE7 processor support", head commit `6a7fbaef3a623e09025880a6dc724e05feed42f7` (2026-09-23), from [ArthurKoba/ghidra](https://github.com/ArthurKoba/ghidra) |
| License | Apache License 2.0 (Ghidra contribution terms; `LICENSE` is Ghidra's Apache-2.0 text) |
| Original author | Arthur Koba ([@ArthurKoba](https://github.com/ArthurKoba), commits as "Arthur Koba"): the SCORE7 SLEIGH specification, cspec, pspec, DWARF map, ldefs, ELF opinion, assembler tests, and a fix to Ghidra's SLEIGH assembler (`StartInstructionValueSolver`) |
| Behavioural reference | MAME's S+core CPU core and disassembler by Sandro Ronco (`src/devices/cpu/score`, BSD-3-Clause), read for instruction semantics, flags, the condition codes and the PCE rule |
| Not used | [sronco/ghidra-score7](https://github.com/sronco/ghidra-score7) (Sandro Ronco's own Ghidra module, 2020-2025): it has no license, so nothing was taken from it |
| Test oracles | GNU binutils 2.45 (`objdump -m score7`) and MAME `unidasm`, run as black boxes; GCC 4.5.4 for score-elf (with binutils 2.20.1, see GHIDRA-RARE.md) as a black box for the calling convention, DWARF numbering and the real-code samples |

The pull request's files are the first commit of the Ghidra-Rare fork, unchanged at their
original paths (`Ghidra/Processors/SCORE7/...` and its change to
`Ghidra/Framework/SoftwareModeling`); every Ghidra-Rare change is a separate commit on top.

## Ghidra-Rare changes

1. **Decoding reworked after differential testing against GNU objdump 2.45** (every 16-bit
   halfword, every 32-bit major opcode with every value of bits 14..0, random words, at both
   halfword positions and in both byte orders):
   - operand syntax as objdump prints it: `[ra, imm]`, `[ra, imm]+` (pre-increment),
     `[ra]+, imm` (post-increment), `[ra]` for 16-bit loads/stores and `push!`/`pop!`, byte
     offsets for `lwp!`/`lhp!`/`swp!`/`shp!`, codes for `syscall`/`sdbbp`/`trap`/`cache`;
   - immediate operands that the pull request read as registers: the bit number of
     `bitclr.c`/`bitset.c`/`bittst.c`/`bittgl.c` and the shift/rotate count of `slli`/`srli`/
     `srai`/`rori`/`roli` and their `.c`/`c.c` forms (it shifted by the value of a register);
   - bit operations exist only in their `.c` forms, `rorc`/`rolc`/`roric`/`rolic` only as `.c`,
     `mulu`/`div`/`divu` only without `.c`; `cmpz*` need rb = 0; system CR-form operations need
     bits 9..8 clear; reserved `cache` operations are rejected;
   - added: the 16-bit custom-engine group (`mtcel!`, `mtceh!`, `mfcel!`, `mfceh!`, `mul.f!`,
     `mulu!` and the multiply-accumulate forms), `mul.f`, the generic `mfce`/`mtce` forms,
     `mfsr`/`mtsr` for every special register, the coprocessor instructions (`mtcN`, `mfcN`,
     `ldcN`, `stcN`, `copN`, `mtccN`, `mfccN`), the named custom-engine instructions (`abs`,
     `clz`, `min`, `max`, `bitrev`, `abs.s`, `add.s`, `sub.s`, `sll.s` and the 22
     multiply-accumulate forms), `cmpis.c` (MAME), and every condition of `br`, `brl`, `t`,
     `mv` and `trap` through condition subtables;
   - **PCE pairs** decode as both 16-bit instructions (`add! r2,r3 || sub! r4,r5`) with p-code
     that executes the first when T is set and the second otherwise (the pull request showed the
     raw halfwords and called a pcodeop); `SCORE7_16.sinc` holds the 16-bit instructions once and
     is included as root instructions, as PCE first halves and as the PCE second-half table.
2. **Semantics** checked in Ghidra's emulator (36 sequences per byte order) and fixed:
   condition flags are separate registers (`V C Z N T`; `mtcr`/`mfcr cr1` and `rte` move them),
   carry of `sll.c`/`srl.c`/`sra.c`/`slli.c`/`srli.c`/`srai.c`/`slli!`/`srli!`, full carry and
   overflow of `addc.c`/`subc.c`, `bittst` N from the operand, the `cnz` condition (CNT = sr0,
   decremented by branches only), rotate semantics instead of pcodeops, `alw`/`asw` as loads and
   stores, `abs`/`clz` in p-code; 16-bit `mul.f!`/`mulu!` as the 32-bit `mul`/`mulu`.
3. **cspec** from GCC 4.5.4 output: stack arguments start at r0+16 (not 4) and 64-bit results
   are r4:r5 with the high word in r4 (the pull request had them swapped).
4. **DWARF map** confirmed against GCC 4.5.4 output (r0-r31 by number).
5. **Stand-alone extension build** (`build.gradle`, `extension.properties`,
   `data/buildLanguage.xml`, `data/sleighArgs.txt`) replacing the in-tree Gradle file.
6. **Removed** the pull request's `src/test` assembler tests, which need the Ghidra source tree's
   test framework. The pull request's assembler fix in `Ghidra/Framework/SoftwareModeling` is
   part of Ghidra itself and cannot ship in an extension (see GHIDRA-RARE.md).

Ghidra-Rare-only files: `GHIDRA-RARE.md`, `CREDITS.md`, `README.md`, `LICENSE`, `build.gradle`,
`extension.properties`, `.gitignore`, `data/languages/SCORE7_16.sinc` (split from
`SCORE7.sinc`), `test/`.
