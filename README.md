# xxyara

**xxyara is a C11 implementation of [YARA-X](https://github.com/VirusTotal/yara-x) 1.23.0.** It has the same rule
language, the same `yr` command-line tool, the same C API (`yara_x.h`) and the same compiled-rules format. It is
built without a Rust toolchain, a WebAssembly runtime or third-party libraries. Its only dependency is
[xxfclib](https://github.com/horsicq/xxfclib), a plain C library.

The goal: **exactly YARA-X's results, faster.**

- **Same results as YARA-X 1.23.0.** Matching rules, pattern offsets and lengths, module fields, error and warning
  texts and every byte of `yr` output are checked against the official binaries on more than 62,000 differential
  test cases.
- **Faster.** On the [benchmarks](#speed), xxyara is faster than YARA-X on all 12 benchmark cases (1.2x to 54x)
  and on every many-rule workload compiled from source (1.1x to 5.4x).
- **Self-contained.** `xxyara.dll` (4.7 MB) and `yr.exe` (6.5 MB) import nothing but `KERNEL32.dll`.
  YARA-X's `yr.exe` is 26.4 MB.
- **Drop-in C API.** `include/yara_x.h` is the YARA-X 1.23.0 C API header. `xxyara.dll` exports the same 55
  functions as YARA-X's `yara_x_capi.dll`, and the xxyara additions live in `include/xxyara_ext.h`. Examples
  for C, C++, Python, C#, PowerShell, Java, Rust and Pascal are in [examples/](examples/README.md).

## Speed

Classic YARA 4.6.0 and YARA-X 1.23.0 (official Windows x64 builds) against xxyara on the same machine (AMD
Ryzen 7 1800X, Windows 11). Each number is the median wall time of the whole command, from process start to the
last line of output. On every row, all three engines report the same matches. The full tables with CPU time and
the method are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Benchmark cases: one file, rules compiled from source

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X |
|---|---:|---:|---:|---|
| 128 literals, 1 GiB | 5.36 s | 2.80 s | **1.37 s** | 2.0x faster |
| 32 `base64` strings, 768 MiB | 4.12 s | 2.56 s | **598 ms** | 4.3x faster |
| 8 bounded regexps, 2 GiB | 11.50 s | 3.15 s | **2.56 s** | 1.2x faster |
| 90 M loop iterations, integer arithmetic | 33.56 s | 2.77 s | **981 ms** | 2.8x faster |
| 128 M nested loop iterations | 28.09 s | 2.00 s | **37 ms** | 54.0x faster |
| 80 M loop iterations, floating point | 20.44 s | 2.06 s | **613 ms** | 3.4x faster |
| 60 M loop iterations calling `math.abs` | 58.17 s | 1.84 s | **305 ms** | 6.0x faster |
| 1.2 M iterations of an 80-clause `and` | 8.93 s | 1.36 s | **43 ms** | 31.3x faster |
| 40 M iterations reading `@a[1]` / `!a[1]` | 8.10 s | 1.99 s | **147 ms** | 13.6x faster |
| 20,000 literals with long identifiers (15 MB source) | error | 9.10 s | **637 ms** | 14.3x faster |
| Bitcoin-address regexp `fullword`, 200 MiB | 37.59 s | 1.56 s | **651 ms** | 2.4x faster |
| `for any i in (0..filesize-1)` 32-bit compare, 200 MiB | 34.71 s | 5.34 s | **391 ms** | 13.6x faster |

YARA 4.6.0 rejects the 20,000-pattern rule: its limit is 10,000 strings per rule. The last two rows are the
examples from the "Better performance" page of the YARA-X documentation.

### Many rules: compiled from source, 100 MB per scan

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X |
|---|---:|---:|---:|---|
| 1,000 literal rules, 100 MB text | 836 ms | 501 ms | **282 ms** | 1.8x faster |
| 20,000 literal rules, 100 MB text | 1.53 s | 1.74 s | **958 ms** | 1.8x faster |
| 100,000 literal rules, 100 MB text | 4.52 s | 5.33 s | **3.10 s** | 1.7x faster |
| 1,000 literal rules that all match | 76.79 s | 1.16 s | **1.02 s** | 1.1x faster |
| 1,000 hex patterns with jumps, 100 MB random | 137.19 s | 1.06 s | **672 ms** | 1.6x faster |
| 1,000 regexp rules, 100 MB random | 849 ms | 1.68 s | **837 ms** | 2.0x faster |
| 1,000 `nocase` rules | 911 ms | 790 ms | **432 ms** | 1.8x faster |
| 1,000 `wide` rules | 718 ms | 535 ms | **250 ms** | 2.1x faster |
| 1,000 `xor` rules | 53.56 s | 3.55 s | **953 ms** | 3.7x faster |
| 1,000 `base64` rules | 570 ms | 305 ms | **155 ms** | 2.0x faster |
| 5,000 mixed rules | **1.66 s** | 4.30 s | 2.55 s | 1.7x faster |
| PE-module rule set over a folder of 500 PE files | 23.21 s | 8.28 s | **1.52 s** | 5.4x faster |

### Compiling rules (`yarac64`, `yr compile`)

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X |
|---|---:|---:|---:|---|
| compile 20,000 literal rules | **1.12 s** | 2.39 s | 1.75 s | 1.4x faster |
| compile 100,000 literal rules | **4.98 s** | 5.97 s | 8.58 s | 1.4x slower |
| compile 5,000 mixed rules | **539 ms** | 2.69 s | 1.64 s | 1.6x faster |

### Precompiled rules (each engine loads its own compiled format)

| Workload | YARA 4.6.0 | YARA-X 1.23.0 | xxyara | xxyara vs YARA-X |
|---|---:|---:|---:|---|
| 1,000 literal rules, 100 MB | 1.14 s | 1.04 s | **549 ms** | 1.9x faster |
| 20,000 literal rules, 100 MB | **1.15 s** | 2.67 s | 1.77 s | 1.5x faster |
| 1,000 regexp rules, 100 MB | 951 ms | **774 ms** | 2.11 s | 2.7x slower |
| 5,000 mixed rules, 100 MB | **1.23 s** | 1.43 s | 2.21 s | 1.5x slower |
| 1,000 `xor` rules, 100 MB | **1.67 s** | 2.70 s | 4.19 s | 1.6x slower |

Loading large precompiled rule sets is the part of xxyara still being optimized.

## Features compared

### At a glance

| | YARA 4.6.0 | YARA-X 1.23.0 | xxyara |
|---|---|---|---|
| Written in | C | Rust | C11 |
| Rule language | YARA 4 | YARA-X (mostly YARA-compatible) | YARA-X 1.23.0 |
| Condition evaluation | bytecode VM | compiled to WebAssembly, run by wasmtime | native C evaluator |
| Third-party dependencies | OpenSSL, jansson; libmagic (optional) | wasmtime and several hundred Rust crates | none (xxfclib only) |
| Windows x64 binaries | `yara64.exe` 2.4 MB | `yr.exe` 26.4 MB, `yara_x_capi.dll` 23.2 MB | `yr.exe` 6.5 MB, `xxyara.dll` 4.7 MB |
| DLLs imported | KERNEL32, ADVAPI32, CRYPT32, bcrypt, USER32, WS2_32, C runtime | KERNEL32, ntdll, bcryptprimitives, combase, shell32, api-ms-win-core-synch | KERNEL32 only |
| License | BSD-3-Clause | BSD-3-Clause | MIT (upstream notices included) |

### Command line

| | YARA 4.6.0 | YARA-X 1.23.0 | xxyara |
|---|---|---|---|
| Tools | `yara`, `yarac` | `yr` | `yr`, with the same commands, options, help and output |
| Commands | scan; compile (`yarac`) | `scan`, `compile`, `check`, `dump`, `fmt`, `fix`, `deps`, `completion` | the same |
| Output formats | text | text, JSON, NDJSON | the same |
| Compiled rules | YARA 4 format | YARA-X format | YARA-X 1.23.0 format ([limits](#known-differences)) |
| Scan a running process (PID) | yes | no | no |

### Libraries and bindings

| | YARA 4.6.0 | YARA-X 1.23.0 | xxyara |
|---|---|---|---|
| C API | libyara (`yr_*`) | `yara_x.h` (`yrx_*`) | `yara_x.h` (`yrx_*`), the same header |
| Shared library | libyara, built from source | `yara_x_capi.dll` | `xxyara.dll` (`libxxyara.so`), the same exports |
| Static library | libyara, built from source | `yara_x_capi.lib` | `xxyara.lib` (`libxxyara.a`) |
| Official bindings | Python (yara-python) | Rust, Python, Go, JavaScript (WebAssembly) | C; tested examples for C++, Python, C#, PowerShell, Java, Rust and Pascal |

### Rule language

Each row was checked by compiling and scanning a small rule with all three engines.

| Feature | YARA 4.6.0 | YARA-X 1.23.0 | xxyara |
|---|:-:|:-:|:-:|
| `with` declarations | — | ✓ | ✓ |
| `for` over integer and string tuples | ✓ | ✓ | ✓ |
| `for` over module arrays and dictionaries | ✓ | ✓ | ✓ |
| `of` over boolean expressions: `any of (a > 1, b)` | — | ✓ | ✓ |
| percentage `of`: `50% of them` | ✓ | ✓ | ✓ |
| `of` over rule-name wildcards: `any of (r*)` | ✓ | — | — |
| `defined` operator | ✓ | ✓ | ✓ |
| `iequals`, `icontains`, `startswith`, `iendswith`, ... | ✓ | ✓ | ✓ |
| `#a in (range)` | ✓ | ✓ | ✓ |
| hex `~` (negated bytes) | ✓ | ✓ | ✓ |
| `xor(1-255)` | ✓ | ✓ | ✓ |
| `base64`, `base64wide` | ✓ | ✓ | ✓ |
| `private` patterns | ✓ | ✓ | ✓ |
| regexp inline flags: `/(?i)abc/` | — | ✓ | ✓ |
| regexp `{,n}` repetition | ✓ | ✓ | ✓ |
| deprecated `entrypoint` keyword | ✓ | — | — |

### Modules (official Windows builds)

| Module | YARA 4.6.0 | YARA-X 1.23.0 | xxyara |
|---|:-:|:-:|:-:|
| `pe` | ✓ | ✓ | ✓ |
| `elf` | ✓ | ✓ | ✓ |
| `dotnet` | ✓ | ✓ | ✓ |
| `macho` | — (build option) | ✓ | ✓ |
| `dex` | — (build option) | ✓ | ✓ |
| `lnk` | — | ✓ | ✓ |
| `crx` | — | ✓ | ✓ |
| `zip` | — | ✓ | ✓ |
| `vt` | — | ✓ | ✓ |
| `cuckoo` | ✓ | ✓ | ✓ |
| `math` | ✓ | ✓ | ✓ |
| `hash` | ✓ | ✓ | ✓ |
| `string` | ✓ | ✓ | ✓ |
| `time` | ✓ | ✓ | ✓ |
| `console` | ✓ | ✓ | ✓ |
| `magic` | non-Windows builds | opt-in (libmagic) | opt-in (libmagic) |
| `olecf`, `vba`, `msi` | — | opt-in | opt-in |

## Compatibility with YARA-X 1.23.0

Each release is checked against the official YARA-X 1.23.0 binaries (`yr.exe` and `yara_x_capi.dll`):

| Check | Result |
|---|---|
| CLI differential matrix: `yr` stdout, stderr, exit code and archive bytes on generated and hand-written rules | 62,290 / 62,317 cases identical |
| &nbsp;&nbsp;scans, diagnostics, formatting, command-line options | 41,028 / 41,028 |
| &nbsp;&nbsp;compiled rules (`yr compile` archives, `scan -C` with archives from both engines) | 21,262 / 21,289 |
| Rule suite: compile, scan, regressions | 268 / 268, 1,158 / 1,158, 4 / 4 |
| `yr dump` module output for sample files | 123 / 123 identical |
| CLI reference comparison | 1,332 / 1,332 |

## Known differences

- **Compiled rules for a few rule shapes.** Of the 6,830 distinct rule sets in the test matrix that YARA-X
  compiles, xxyara writes all of them as archives, and they are byte-identical to YARA-X's. It loads YARA-X's
  archives of all but one. These shapes are still missing, and they compile and scan correctly from source:
  - shifts (`<<`, `>>`) in rules that also use a module;
  - `for N` / `for N%` loops over module arrays and dictionaries, e.g. `for 1 s in pe.sections`;
  - a capture group at the start of an alternation branch, e.g. `/(caf)e|zz/`.

  27 of the matrix's 21,000 compiled-rule cases still differ from YARA-X in at least one step, e.g. large
  gap bounds or module-field shapes.
- **Loading large precompiled rule sets** is slower than YARA-X for regexp, mixed and `xor` rule sets (see
  [above](#precompiled-rules-each-engine-loads-its-own-compiled-format)).
- **Platforms.** Windows x64 with Visual Studio 2022 is the tested platform. Other systems build with xxfclib's
  POSIX backends but are not part of the regular test cycle yet.

## Building

Requires CMake 3.16+, a C11 compiler and the `xxfclib` source tree next to `xxyara`:

```sh
git clone https://github.com/horsicq/xxfclib
git clone https://github.com/horsicq/xxyara
cd xxyara
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

This builds:
- `xxyara.dll` and its import library `xxyara.dll.lib`;
- the static `xxyara.lib`;
- `yr.exe`;
- `xxyara.exe`, the console application;
- the examples and the tests.

Options, the C runtime and linking without CMake: [docs/BUILD.md](docs/BUILD.md).

## Usage

The command line is YARA-X's. It comes as two programs built from the same sources:
- `xxyara` is the console application. It has `yr`'s commands, options and output; only its banner,
  `--version` line and program name differ;
- `yr` prints exactly what YARA-X's `yr` prints, banner included. The parity tests compare its output with
  the official binary's.

`yr` is a drop-in replacement for scripts and CI jobs that call YARA-X's `yr`. `xxyara` is the branded tool;
it can sit on `PATH` next to the official `yr`. Its help starts with:

```
xxyara 0.1.0, the pattern matching swiss army knife (YARA-X 1.23.0 compatible).

Copyright (c) 2026 hors
Based on the original YARA-X by Victor M. Alvarez <vmalvarez@virustotal.com>
https://github.com/horsicq/xxyara
```

```sh
xxyara scan rules.yar file_or_directory
xxyara --version
```

The same commands with `yr`:

```sh
yr scan rules.yar file_or_directory
yr scan -s --output-format ndjson rules.yar samples/
yr compile rules.yar -o rules.yarc
yr scan -C rules.yarc samples/
yr dump -m pe sample.exe
yr fmt rules.yar
```

### C

```c
#include <stdio.h>
#include <yara_x.h>

static void on_match(const struct YRX_RULE *rule, void *user_data)
{
    const uint8_t *name;
    size_t length;
    (void)user_data;
    if (yrx_rule_identifier(rule, &name, &length) == YRX_SUCCESS)
        printf("%.*s\n", (int)length, (const char *)name);
}

int main(void)
{
    struct YRX_RULES *rules = NULL;
    struct YRX_SCANNER *scanner = NULL;
    const uint8_t data[] = "hello world";
    if (yrx_compile("rule hello { strings: $a = \"hello\" condition: $a }", &rules) != YRX_SUCCESS) {
        fprintf(stderr, "%s\n", yrx_last_error());
        return 1;
    }
    yrx_scanner_create(rules, &scanner);
    yrx_scanner_on_matching_rule(scanner, on_match, NULL);
    yrx_scanner_scan(scanner, data, sizeof(data) - 1);
    yrx_scanner_destroy(scanner);
    yrx_rules_destroy(rules);
    return 0;
}
```

Link it with `xxyara::shared` or `xxyara::xxyara` in CMake, or see [docs/BUILD.md](docs/BUILD.md). From C++, include
`yara_x.h` inside `extern "C" { }`, as [examples/cpp/scan.cpp](examples/cpp/scan.cpp) does.

### Python (ctypes, no packages)

```python
import ctypes

lib = ctypes.CDLL("./xxyara.dll")  # a path to xxyara.dll (libxxyara.so on Linux)
lib.yrx_scanner_scan.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
RULE_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)


@RULE_CALLBACK
def on_rule(rule, user_data):
    name, length = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
    lib.yrx_rule_identifier(ctypes.c_void_p(rule), ctypes.byref(name), ctypes.byref(length))
    print(ctypes.string_at(name, length.value).decode())


rules, scanner = ctypes.c_void_p(), ctypes.c_void_p()
lib.yrx_compile(b'rule hello { strings: $a = "hello" condition: $a }', ctypes.byref(rules))
lib.yrx_scanner_create(rules, ctypes.byref(scanner))
lib.yrx_scanner_on_matching_rule(scanner, on_rule, None)
lib.yrx_scanner_scan(scanner, b"hello world", 11)
lib.yrx_scanner_destroy(scanner)
lib.yrx_rules_destroy(rules)
```

### C# (P/Invoke)

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Hello
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void RuleCallback(IntPtr rule, IntPtr userData);

    [DllImport("xxyara")] static extern int yrx_compile(byte[] source, out IntPtr rules);
    [DllImport("xxyara")] static extern int yrx_scanner_create(IntPtr rules, out IntPtr scanner);
    [DllImport("xxyara")] static extern int yrx_scanner_on_matching_rule(IntPtr scanner, RuleCallback callback, IntPtr userData);
    [DllImport("xxyara")] static extern int yrx_scanner_scan(IntPtr scanner, byte[] data, UIntPtr length);
    [DllImport("xxyara")] static extern int yrx_rule_identifier(IntPtr rule, out IntPtr name, out UIntPtr length);
    [DllImport("xxyara")] static extern void yrx_scanner_destroy(IntPtr scanner);
    [DllImport("xxyara")] static extern void yrx_rules_destroy(IntPtr rules);

    public static void Main()
    {
        yrx_compile(Encoding.UTF8.GetBytes("rule hello { strings: $a = \"hello\" condition: $a }\0"), out IntPtr rules);
        yrx_scanner_create(rules, out IntPtr scanner);
        RuleCallback onRule = (rule, userData) =>
        {
            yrx_rule_identifier(rule, out IntPtr name, out UIntPtr length);
            Console.WriteLine(Marshal.PtrToStringUTF8(name, (int)length));
        };
        yrx_scanner_on_matching_rule(scanner, onRule, IntPtr.Zero);
        byte[] data = Encoding.UTF8.GetBytes("hello world");
        yrx_scanner_scan(scanner, data, (UIntPtr)data.Length);
        GC.KeepAlive(onRule);
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}
```

### More languages

Complete programs that print every match with its offset and length, each tested against `xxyara.dll`:
- [Python](examples/python/scan.py);
- [C#](examples/csharp/Scan.cs) and [PowerShell](examples/powershell/scan.ps1);
- [Java 22+ (Foreign Function & Memory API)](examples/java/Scan.java);
- [Rust (FFI, no crates)](examples/rust/src/main.rs);
- [Free Pascal / Delphi](examples/pascal/scan.pas);
- [C++](examples/cpp/scan.cpp).

How to build and run each: [examples/README.md](examples/README.md).

## License

xxyara's own code is [MIT](LICENSE). It follows YARA-X's design and behaviour, and the upstream notices are
included: [YARA-X](LICENSE.YARA-X), [encoding_rs](LICENSE.ENCODING_RS), [regex-syntax](LICENSE.REGEX-SYNTAX),
[unicode-width](LICENSE.UNICODE-WIDTH) and [annotate-snippets](LICENSE.ANNOTATE-SNIPPETS). YARA and YARA-X are
VirusTotal projects; xxyara is an independent implementation.
