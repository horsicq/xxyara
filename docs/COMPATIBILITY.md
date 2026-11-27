# Compatibility with YARA-X 1.23.0


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
  [benchmarks](BENCHMARKS.md)).
- **Platforms.** Windows x64 with Visual Studio 2022 is the tested platform. Other systems build with xxfclib's
  POSIX backends but are not part of the regular test cycle yet.
