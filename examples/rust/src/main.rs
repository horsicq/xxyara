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

//! xxyara example in Rust: the YARA-X C API of xxyara through FFI, no crates needed.
//! usage: scan <rules.yar> <file>
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::process::ExitCode;

#[repr(C)]
struct YrxMatch {
    offset: usize,
    length: usize,
    xor_key: i16,
}

type RuleCallback = extern "C" fn(*const c_void, *mut c_void);
type PatternCallback = extern "C" fn(*const c_void, *mut c_void);
type MatchCallback = extern "C" fn(*const YrxMatch, *mut c_void);
type NameGetter = unsafe extern "C" fn(*const c_void, *mut *const u8, *mut usize) -> c_int;

extern "C" {
    fn yrx_compile(src: *const c_char, rules: *mut *mut c_void) -> c_int;
    fn yrx_rules_destroy(rules: *mut c_void);
    fn yrx_scanner_create(rules: *const c_void, scanner: *mut *mut c_void) -> c_int;
    fn yrx_scanner_destroy(scanner: *mut c_void);
    fn yrx_scanner_on_matching_rule(scanner: *mut c_void, callback: RuleCallback, user_data: *mut c_void) -> c_int;
    fn yrx_scanner_scan_file(scanner: *mut c_void, path: *const c_char) -> c_int;
    fn yrx_rule_identifier(rule: *const c_void, ident: *mut *const u8, len: *mut usize) -> c_int;
    fn yrx_rule_iter_patterns(rule: *const c_void, callback: PatternCallback, user_data: *mut c_void) -> c_int;
    fn yrx_pattern_identifier(pattern: *const c_void, ident: *mut *const u8, len: *mut usize) -> c_int;
    fn yrx_pattern_iter_matches(pattern: *const c_void, callback: MatchCallback, user_data: *mut c_void) -> c_int;
    fn yrx_last_error() -> *const c_char;
}

/// What the callbacks collect while the scan runs.
struct State {
    lines: Vec<String>,
    pattern: String,
}

unsafe fn name(getter: NameGetter, handle: *const c_void) -> Option<String> {
    let mut text: *const u8 = std::ptr::null();
    let mut length = 0usize;
    if getter(handle, &mut text, &mut length) != 0 {
        return None;
    }
    Some(String::from_utf8_lossy(std::slice::from_raw_parts(text, length)).into_owned())
}

fn last_error() -> String {
    let message = unsafe { yrx_last_error() };
    if message.is_null() {
        "unknown error".to_string()
    } else {
        unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned()
    }
}

extern "C" fn on_match(found: *const YrxMatch, user_data: *mut c_void) {
    let state = unsafe { &mut *(user_data as *mut State) };
    let found = unsafe { &*found };
    let line = format!("  {} at {}, {} bytes", state.pattern, found.offset, found.length);
    state.lines.push(line);
}

extern "C" fn on_pattern(pattern: *const c_void, user_data: *mut c_void) {
    if let Some(identifier) = unsafe { name(yrx_pattern_identifier, pattern) } {
        // Do not keep a reference to the state across the call back into C.
        unsafe { (*(user_data as *mut State)).pattern = identifier };
        unsafe { yrx_pattern_iter_matches(pattern, on_match, user_data) };
    }
}

extern "C" fn on_rule(rule: *const c_void, user_data: *mut c_void) {
    if let Some(identifier) = unsafe { name(yrx_rule_identifier, rule) } {
        unsafe { (*(user_data as *mut State)).lines.push(identifier) };
        unsafe { yrx_rule_iter_patterns(rule, on_pattern, user_data) };
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: scan <rules.yar> <file>");
        return ExitCode::from(2);
    }
    let source = match std::fs::read_to_string(&args[1]) {
        Ok(text) => CString::new(text).expect("the rules contain a NUL byte"),
        Err(error) => {
            eprintln!("cannot read {}: {error}", args[1]);
            return ExitCode::from(1);
        }
    };
    let path = CString::new(args[2].as_str()).expect("the path contains a NUL byte");
    let mut state = State { lines: Vec::new(), pattern: String::new() };
    let mut status = 1u8;
    unsafe {
        let mut rules = std::ptr::null_mut();
        if yrx_compile(source.as_ptr(), &mut rules) != 0 {
            eprintln!("{}", last_error());
            return ExitCode::from(1);
        }
        let mut scanner = std::ptr::null_mut();
        if yrx_scanner_create(rules, &mut scanner) == 0 {
            yrx_scanner_on_matching_rule(scanner, on_rule, &mut state as *mut State as *mut c_void);
            if yrx_scanner_scan_file(scanner, path.as_ptr()) == 0 {
                status = 0;
            } else {
                eprintln!("{}", last_error());
            }
            yrx_scanner_destroy(scanner);
        } else {
            eprintln!("{}", last_error());
        }
        yrx_rules_destroy(rules);
    }
    for line in &state.lines {
        println!("{line}");
    }
    ExitCode::from(status)
}
