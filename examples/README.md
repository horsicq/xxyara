# xxyara examples

Every example does the same thing through the YARA-X C API: compile `data/rules.yar`, scan `data/sample.txt`,
and print each matching rule with its pattern matches. Every one prints exactly [data/expected.txt](data/expected.txt):

```
hello_world
  $hello at 0, 5 bytes
  $hello at 13, 5 bytes
  $world at 6, 5 bytes
  $world at 19, 5 bytes
```

| Language | File | Uses | Checked with |
|---|---|---|---|
| C | [c/scan.c](c/scan.c) | static library or `xxyara.dll` | MSVC 2022 (CTest `xxyara_example_c_static`, `xxyara_example_c_shared`) |
| C++ | [cpp/scan.cpp](cpp/scan.cpp) | RAII classes over the C API | MSVC 2022 (CTest `xxyara_example_cpp`) |
| Python | [python/scan.py](python/scan.py) | `ctypes`, standard library only | Python 3.13 (CTest `xxyara_example_python`) |
| C# | [csharp/Scan.cs](csharp/Scan.cs) | P/Invoke | .NET 10 through PowerShell 7 `Add-Type` |
| PowerShell | [powershell/scan.ps1](powershell/scan.ps1) | compiles `Scan.cs` with `Add-Type` | PowerShell 7.6 |
| Java | [java/Scan.java](java/Scan.java) | Foreign Function & Memory API (Java 22+), no JNI | Java 24 |
| Rust | [rust/](rust/) | `extern "C"`, no crates | Rust 1.97 (`x86_64-pc-windows-gnu`; `build.rs` also handles MSVC) |
| Pascal | [pascal/scan.pas](pascal/scan.pas) | `external` functions, Free Pascal and Delphi | Free Pascal 3.2.2 (win64) |

The C, C++ and Python examples are built and run as tests in the main build (`ctest -R example`). The commands
below assume a release build in `build/`, so the libraries are in `build/Release/`. Run them from
`examples/data`.

## C and C++

They are built with xxyara: `build/examples/Release/scan_static.exe`, `scan_shared.exe` (next to a copy of
`xxyara.dll`) and `scan_cpp.exe`.

```sh
../../build/examples/Release/scan_shared.exe rules.yar sample.txt
```

## Python

```sh
python ../python/scan.py rules.yar sample.txt ../../build/Release/xxyara.dll
```

The same script also runs unchanged with YARA-X's own `yara_x_capi.dll`.

## C# and PowerShell

```sh
pwsh ../powershell/scan.ps1 -Rules rules.yar -File sample.txt -Library ../../build/Release/xxyara.dll
```

In a .NET project, add `Scan.cs` and copy `xxyara.dll` next to the executable.

## Java

```sh
java --enable-native-access=ALL-UNNAMED ../java/Scan.java ../../build/Release/xxyara.dll rules.yar sample.txt
```

## Rust

```sh
cd ../rust
XXYARA_LIB_DIR=../../build/Release cargo build --release --offline   # needs no crates
cd ../data
PATH="../../build/Release:$PATH" ../rust/target/release/scan rules.yar sample.txt
```

## Pascal

Free Pascal, 64-bit Windows:

```sh
fpc -Px86_64 -Twin64 -FE../pascal/out ../pascal/scan.pas
cp ../../build/Release/xxyara.dll ../pascal/out/
../pascal/out/scan.exe rules.yar sample.txt
```
