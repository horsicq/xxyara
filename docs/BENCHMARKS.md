# Benchmarks

xxyara compared with classic YARA 4.6.0 and YARA-X 1.23.0, on the official Windows x64 builds of both.

## How the numbers were taken

- Machine: AMD Ryzen 7 1800X Eight-Core Processor (8 cores, 16 threads), 64 GB RAM, Windows 11 (build 26100). The inputs were in the OS file
  cache. Other jobs were running on the machine at the same time, so treat differences under about 10% as noise.
- Every number is the **median of 3 runs after 1 warm-up**, timing the whole command: process start, reading the
  rules, compiling or loading them, scanning, and writing the output.
- The engines run one after another, in an order that rotates between repetitions.
- CPU is the process's user plus kernel time (`GetProcessTimes`). It can exceed wall time when an engine uses
  several threads.
- "Same matches": all three engines reported the same (rule, file) pairs. Every row says yes.
- Commands:
  - YARA: `yara64 -w RULES TARGET`; compiled rules `yarac64 RULES OUT` and `yara64 -C OUT TARGET`.
  - YARA-X and xxyara: `yr scan --disable-warnings RULES TARGET`; compiled rules `yr compile RULES -o OUT` and
    `yr scan -C OUT TARGET`.
- Engines:
  - YARA 4.6.0: `yara64.exe` from github.com/VirusTotal/yara, release v4.6.0.
  - YARA-X 1.23.0: the official `yr.exe`.
  - xxyara: `yr.exe` built with Visual Studio 2022, Release.
- Date: 2026-11-16.

## Benchmark cases (one file, rules compiled from source)

Each case targets one part of the engine: the literal, `base64` and regexp prefilters over large inputs, and
the condition evaluator in loops with arithmetic, floating point, module calls, long boolean chains and match
offsets. Case 10 compiles 20,000 patterns. Cases 11 and 12 are the two examples from the "Better performance"
page of the YARA-X documentation: the Bitcoin-address regexp and the `0xCAFEBABE` loop.

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X | CPU (YARA / YARA-X / xxyara) | same matches |
|---|---:|---:|---:|---|---|---|
| 128 literals, 1 GiB | 5.36 s | 2.80 s | **1.37 s** | 2.0x faster | 5.03 s / 2.53 s / 1.27 s | yes |
| 32 `base64` strings, 768 MiB | 4.12 s | 2.56 s | **598 ms** | 4.3x faster | 3.69 s / 2.31 s / 578 ms | yes |
| 8 bounded regexps, 2 GiB | 11.50 s | 3.15 s | **2.56 s** | 1.2x faster | 10.19 s / 2.67 s / 2.08 s | yes |
| 90 M loop iterations, integer arithmetic | 33.56 s | 2.77 s | **981 ms** | 2.8x faster | 25.30 s / 2.48 s / 500 ms | yes |
| 128 M nested loop iterations | 28.09 s | 2.00 s | **37 ms** | 54.0x faster | 23.14 s / 1.97 s / 16 ms | yes |
| 80 M loop iterations, floating point | 20.44 s | 2.06 s | **613 ms** | 3.4x faster | 19.42 s / 1.91 s / 406 ms | yes |
| 60 M loop iterations calling `math.abs` | 58.17 s | 1.84 s | **305 ms** | 6.0x faster | 47.38 s / 1.81 s / 203 ms | yes |
| 1.2 M iterations of an 80-clause `and` | 8.93 s | 1.36 s | **43 ms** | 31.3x faster | 8.36 s / 1.34 s / 31 ms | yes |
| 40 M iterations reading `@a[1]` / `!a[1]` | 8.10 s | 1.99 s | **147 ms** | 13.6x faster | 7.86 s / 1.83 s / 141 ms | yes |
| 20,000 literals with long identifiers (15 MB source) | error | 9.10 s | **637 ms** | 14.3x faster | n/a / 8.36 s / 547 ms | yes |
| Bitcoin-address regexp `fullword`, 200 MiB | 37.59 s | 1.56 s | **651 ms** | 2.4x faster | 28.27 s / 1.25 s / 469 ms | yes |
| `for any i in (0..filesize-1)` 32-bit compare, 200 MiB | 34.71 s | 5.34 s | **391 ms** | 13.6x faster | 28.92 s / 4.88 s / 188 ms | yes |

YARA 4.6.0 rejects case 10: `too many strings in rule "perf_many_patterns" (limit: 10000)`.

## Many rules

Generated rule sets over 100 MB of text or random data (one file), compiled from source in the same process. The PE row scans a folder of 500 PE files with a rule set that uses the `pe` module.

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X | CPU (YARA / YARA-X / xxyara) | same matches |
|---|---:|---:|---:|---|---|---|
| 1,000 literal rules, 100 MB text | 836 ms | 501 ms | **282 ms** | 1.8x faster | 594 ms / 484 ms / 141 ms | yes |
| 20,000 literal rules, 100 MB text | 1.53 s | 1.74 s | **958 ms** | 1.8x faster | 1.31 s / 3.02 s / 734 ms | yes |
| 100,000 literal rules, 100 MB text | 4.52 s | 5.33 s | **3.10 s** | 1.7x faster | 4.08 s / 13.67 s / 2.88 s | yes |
| 1,000 literal rules that all match | 76.79 s | 1.16 s | **1.02 s** | 1.1x faster | 52.33 s / 734 ms / 391 ms | yes |
| 1,000 hex patterns with jumps, 100 MB random | 137.19 s | 1.06 s | **672 ms** | 1.6x faster | 92.47 s / 828 ms / 453 ms | yes |
| 1,000 regexp rules, 100 MB random | 849 ms | 1.68 s | **837 ms** | 2.0x faster | 703 ms / 1.42 s / 531 ms | yes |
| 1,000 `nocase` rules | 911 ms | 790 ms | **432 ms** | 1.8x faster | 609 ms / 625 ms / 234 ms | yes |
| 1,000 `wide` rules | 718 ms | 535 ms | **250 ms** | 2.1x faster | 609 ms / 547 ms / 188 ms | yes |
| 1,000 `xor` rules | 53.56 s | 3.55 s | **953 ms** | 3.7x faster | 41.31 s / 2.05 s / 438 ms | yes |
| 1,000 `base64` rules | 570 ms | 305 ms | **155 ms** | 2.0x faster | 531 ms / 438 ms / 125 ms | yes |
| 5,000 mixed rules | **1.66 s** | 4.30 s | 2.55 s | 1.7x faster | 969 ms / 2.31 s / 859 ms | yes |
| PE-module rule set over a folder of 500 PE files | 23.21 s | 8.28 s | **1.52 s** | 5.4x faster | 31.09 s / 6.81 s / 2.45 s | yes |

## Compiling rules

`yarac64 RULES OUT` and `yr compile RULES -o OUT`.

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X | CPU (YARA / YARA-X / xxyara) | same matches |
|---|---:|---:|---:|---|---|---|
| compile 20,000 literal rules | **1.12 s** | 2.39 s | 1.75 s | 1.4x faster | 578 ms / 2.59 s / 1.12 s | yes |
| compile 100,000 literal rules | **4.98 s** | 5.97 s | 8.58 s | 1.4x slower | 3.56 s / 12.59 s / 6.14 s | yes |
| compile 5,000 mixed rules | **539 ms** | 2.69 s | 1.64 s | 1.6x faster | 188 ms / 2.00 s / 1.09 s | yes |

## Precompiled rules

Each engine scans 100 MB with rules it compiled itself (the formats differ: YARA 4 for `yara64`, YARA-X for both `yr`). Loading large compiled rule sets is the part of xxyara still being optimized.

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X | CPU (YARA / YARA-X / xxyara) | same matches |
|---|---:|---:|---:|---|---|---|
| 1,000 literal rules, 100 MB | 1.14 s | 1.04 s | **549 ms** | 1.9x faster | 625 ms / 469 ms / 234 ms | yes |
| 20,000 literal rules, 100 MB | **1.15 s** | 2.67 s | 1.77 s | 1.5x faster | 656 ms / 2.19 s / 1.25 s | yes |
| 1,000 regexp rules, 100 MB | 951 ms | **774 ms** | 2.11 s | 2.7x slower | 609 ms / 438 ms / 2.81 s | yes |
| 5,000 mixed rules, 100 MB | **1.23 s** | 1.43 s | 2.21 s | 1.5x slower | 797 ms / 859 ms / 1.91 s | yes |
| 1,000 `xor` rules, 100 MB | **1.67 s** | 2.70 s | 4.19 s | 1.6x slower | 1.17 s / 1.28 s / 1.91 s | yes |
