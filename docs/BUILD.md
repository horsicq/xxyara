# Building xxyara

Requires CMake 3.16+, a C11 compiler and the sibling `xxfclib` source tree
(`../xxfclib` by default; set `XXYARA_XXFCLIB_SOURCE_DIR` for another location).

Nothing else is needed. xxfclib provides everything xxyara uses: hashing,
compression, XML, regular expressions, and ASN.1, X.509 and Authenticode for
PE signatures. There is no zlib, OpenSSL, LibXml2, PCRE2 or Windows crypto
dependency. With MSVC for x64, `xxyara.dll`, `yr.exe` and `xxyara.exe` contain no Microsoft
C runtime at all and import nothing but `KERNEL32.dll`: the C runtime comes
from xxfclib (see [The C runtime](#the-c-runtime)).
On Windows (MSVC, MinGW) the three carry a version resource: CompanyName `hors`,
LegalCopyright `Copyright (c) 2026 hors`, the version of the CMake project, and a
description that credits YARA-X by Victor M. Alvarez.

The tested platform is Windows x64 with Visual Studio 2022. On other systems
the build selects xxfclib's POSIX backends, but those builds are not part of
the regular test cycle yet.

Run from the `xxyara` directory:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

## Outputs

| File (MSVC) | Elsewhere | What it is |
|---|---|---|
| `xxyara.dll` | `libxxyara.so` | shared library: the whole YARA-X C API plus the xxyara extensions, nothing else to ship |
| `xxyara.dll.lib` | — | import library of `xxyara.dll` (named like YARA-X's `yara_x_capi.dll.lib`) |
| `xxyara.lib` + `xxyara_xxfclib.lib` | `libxxyara.a` + `libxxyara_xxfclib.a` | static library and the xxfclib part it needs |
| `xxyara_crt.lib` | — | xxfclib's C runtime for links without Microsoft's (`XXYARA_NO_CRT`) |
| `yr.exe` | `yr` | the command-line tool; prints exactly what YARA-X's `yr` prints, banner included |
| `xxyara.exe` | `xxyara` | the console application: `yr` under its own name, banner and `--version` |
| `examples/scan_*.exe` | `examples/scan_*` | the C and C++ examples |

`xxyara.dll` exports the same 55 functions as YARA-X 1.23.0's `yara_x_capi.dll`,
under the same names. A program built against YARA-X's DLL can therefore use a
copy of `xxyara.dll` renamed to `yara_x_capi.dll`.

With CMake, link `xxyara::xxyara` (static) or `xxyara::shared` (the DLL).
Without CMake:

```sh
cl /I include app.c xxyara.dll.lib                  # shared: ship xxyara.dll next to app.exe
cl /MT /I include app.c xxyara.lib xxyara_xxfclib.lib  # static, with Microsoft's C runtime
cl /MT /GS- /Zl /I include app.c /link /NODEFAULTLIB xxyara.lib xxyara_xxfclib.lib xxyara_crt.lib kernel32.lib  # static, no C runtime
```

The static libraries are compiled for the static C runtime (`/MT`) without
default-library records, so a program can link them with Microsoft's `/MT`
runtime or, with `/NODEFAULTLIB`, with `xxyara_crt.lib` instead (never both).
To build everything with Microsoft's DLL runtime, configure with
`-DXXYARA_NO_CRT=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL`. When xxyara
is added to another project with `add_subdirectory`, it uses that project's
runtime setting and `XXYARA_NO_CRT` is OFF.

## The C runtime

With `XXYARA_NO_CRT` (ON by default for top-level MSVC x64 builds) the DLL,
`yr.exe`, the C examples and the tests link with `/NODEFAULTLIB`: no
`ucrt`/`vcruntime`/`msvcrt` DLL and no static `libucrt`/`libvcruntime`/`libcmt`.
Every C runtime function they call comes from xxfclib:

- `src/crt` (portable, `xx_crt_` names): printf formatting, `sscanf`, `strtod`,
  the `strtol` family, `qsort`, the character classes, `mem*`/`strlen`, the
  math functions, `gmtime`/`strftime`;
- `src/crt/platforms` (Windows, standard names, `xxyara_crt.lib`): the stdio
  streams, `malloc`, the program and DLL entry points, the command line, the
  thread-local storage directory, environment and file-system calls.

The results are those of Microsoft's Universal CRT, which YARA-X's official
binaries link: printf's float conversions are exact with UCRT's rounding and
spellings, `strtod` keeps UCRT's 768-digit limit and its tie rounding, `qsort`
orders equal elements like UCRT's quicksort. xxfclib's
`tests/crt/crt_ucrt_diff.c` (CTest `xxyara_crt_ucrt_diff`) compares the two.
`log2` is xxfclib's `xx_ms_log2`, which reproduces UCRT's `log2` bit for bit
(UCRT's is not correctly rounded, and `math.entropy` carries its last bits);
the CTest `xxyara_ms_log2_ucrt` proves it against the real UCRT. What exists
only under standard names (streams, environment, paths, `stat`, errno) is
checked by `xxyara_crt_platform_probe`: one probe program built against
Microsoft's runtime and against xxfclib's must print the same. The whole
layer, its function map and the proofs are described in xxfclib's
`docs/CRT.md`.

The C++ example keeps Microsoft's C and C++ runtime: it uses the C++ standard
library and exceptions.

`include/yara_x.h` is the plain C header of the YARA-X C API. From C++, include
it inside `extern "C" { ... }`.

## Options

| Option | Default | Effect |
|---|---|---|
| `XXYARA_BUILD_CLI` | ON | build `yr` |
| `XXYARA_BUILD_CONSOLE` | ON at top level | build `xxyara`, the console application |
| `XXYARA_BUILD_SHARED` | ON at top level | build `xxyara.dll` / `libxxyara.so` |
| `XXYARA_BUILD_EXAMPLES` | ON at top level | build the C and C++ examples |
| `XXYARA_BUILD_TESTS` | ON at top level | build the tests |
| `XXYARA_ENABLE_MAGIC` | OFF | `magic` module (needs libmagic) |
| `XXYARA_ENABLE_OLECF`, `XXYARA_ENABLE_VBA`, `XXYARA_ENABLE_MSI` | OFF | modules that YARA-X also leaves out of its default build |
| `XXYARA_ENABLE_TEST_PROTO` | OFF | the test-only `test_proto2` / `test_proto3` modules |
| `XXYARA_ENABLE_PROFILING` | OFF | rule profiling in the C API |
| `XXYARA_NO_CRT` | ON for top-level MSVC x64 | link without Microsoft's C runtime ([details](#the-c-runtime)); OFF links it statically (`/MT`) |

The executables built here reserve an 8 MiB stack (`/STACK:8388608` with
MSVC). Applications that evaluate very deeply nested conditions should do the
same.

Native regular expressions use explicit match budgets and report exhaustion as
an error. Counted subjects are limited to `INT32_MAX` bytes.

Examples for C, C++, Python, C#, PowerShell, Java, Rust and Pascal are in
[examples/](../examples/README.md). See the [README](../README.md) for usage.
