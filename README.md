# SCORE7 (Sunplus S+core7) processor module for Ghidra

Ghidra support for the Sunplus S+core7 (SCORE7) 32-bit RISC instruction set, with its mixed
16-bit and 32-bit instructions and parallel-conditional-execution (PCE) pairs. S+core7 cores
were used in Sunplus SoCs (for example the SPG29x family in handheld game and learning systems).

It was written by Arthur Koba as Ghidra pull request
[#9671](https://github.com/NationalSecurityAgency/ghidra/pull/9671). This copy is the Ghidra-Rare
fork, which tested it against GNU binutils 2.45, MAME's S+core core and disassembler and code
compiled with GCC 4.5.4, and fixed what the tests found; see [GHIDRA-RARE.md](GHIDRA-RARE.md) for
the results and [CREDITS.md](CREDITS.md) for the authors and the list of changes.

## Install

Download the zip for your Ghidra version from this repository's Releases page (built for
Ghidra 12.1.3, 12.1.4 and 12.2) and install it with *File > Install Extensions*. To build it
yourself: `GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension`.

## Languages

| Language ID | Description | ELF auto-select |
|---|---|---|
| `SCORE7:LE:32:default` | S+core7, little-endian | e_machine 135 (EM_SCORE7), ELF32 LSB |
| `SCORE7:BE:32:default` | S+core7, big-endian | e_machine 135, ELF32 MSB |

## Known limitations

These were collected from the pull request description ("Scope and known limitations") and
Ghidra-Rare's own testing.

| Limitation | Status |
|---|---|
| System, custom-engine, atomic, parity/PCE and other operations represented by pcodeops | **Fixed** where a non-GPL source describes them: PCE pairs execute one of their two instructions, rotates, `alw`/`asw`, `abs`, `clz`, the multiply forms, `mtcr`/`mfcr` of the flags and `rte` are p-code. **Remaining** as pcodeops, because no public non-GPL description of their effect exists: the custom-engine multiply-accumulate and saturating forms, `min`/`max`/`bitrev`, `lcb`...`sce`, `ceinst`; and system operations outside the core (`syscall`, `trap`, `sdbbp`, `pflush`, `cache`, TLB operations, `drte`, `sleep`, the coprocessor instructions) |
| SCORE7-specific ELF relocation processing not included | **Remaining, not needed for executables**: the tested programs are linked executables and import without relocations; object files (`.o`) would show unrelocated `j`/`jl`/`la` targets |
| Coprocessor, floating-point/DSP and custom accelerator families not complete | **Fixed** for decoding: every coprocessor and custom-engine instruction objdump knows decodes; semantics as above |
| The assembler needs a fix to Ghidra's `StartInstructionValueSolver` (part of the pull request) | **Remaining (Ghidra core)**: an extension cannot change Ghidra's assembler; disassembly, decompilation and emulation do not depend on it |

Remaining gaps found by testing are listed in [GHIDRA-RARE.md](GHIDRA-RARE.md).
