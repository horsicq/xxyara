// Copyright (c) 2026 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Links the xxyara shared library. Set XXYARA_LIB_DIR to the folder that holds it:
// - x86_64-pc-windows-msvc: the import library xxyara.dll.lib;
// - x86_64-pc-windows-gnu: xxyara.dll itself (GNU ld links a DLL directly);
// - Linux and others: libxxyara.so.
// `+verbatim` passes the file name unchanged, so the static xxyara.lib in the same folder is never picked.
fn main() {
    println!("cargo:rerun-if-env-changed=XXYARA_LIB_DIR");
    if let Ok(dir) = std::env::var("XXYARA_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
    }
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("windows-msvc") {
        println!("cargo:rustc-link-lib=dylib:+verbatim=xxyara.dll.lib");
    } else if target.contains("windows-gnu") {
        println!("cargo:rustc-link-lib=dylib:+verbatim=xxyara.dll");
    } else {
        println!("cargo:rustc-link-lib=dylib=xxyara");
    }
}
