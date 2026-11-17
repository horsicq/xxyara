# Building xxyara

Requires CMake 3.16+, a C11 compiler and the sibling `xxfclib` source tree
(`../xxfclib` by default; set `XXYARA_XXFCLIB_SOURCE_DIR` for another location).

Nothing else is needed. xxfclib provides everything xxyara uses: hashing,
compression, XML, regular expressions, and ASN.1, X.509 and Authenticode for
PE signatures. There is no zlib, OpenSSL, LibXml2, PCRE2 or Windows crypto
dependency. With MSVC the C runtime is linked statically (`/MT`), so
`xxyara.dll`, `yr.exe` and `xxyara.exe` import nothing but `KERNEL32.dll`.
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
cl /MT /I include app.c xxyara.lib xxyara_xxfclib.lib  # static
```

The static libraries are built with the static C runtime (`/MT`), so programs
that link them statically must use `/MT` too. To build everything with the DLL
runtime instead, configure with `-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL`.
When xxyara is added to another project with `add_subdirectory`, it uses that
project's runtime setting.

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

The executables built here reserve an 8 MiB stack (`/STACK:8388608` with
MSVC). Applications that evaluate very deeply nested conditions should do the
same.

Native regular expressions use explicit match budgets and report exhaustion as
an error. Counted subjects are limited to `INT32_MAX` bytes.

Examples for C, C++, Python, C#, PowerShell, Java, Rust and Pascal are in
[examples/](../examples/README.md). See the [README](../README.md) for usage.
