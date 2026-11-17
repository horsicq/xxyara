# Copyright (c) 2026 hors<horsicq@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""xxyara example in Python: the shared library through ctypes (standard library only).

usage: python scan.py <rules.yar> <file> [path to xxyara.dll / libxxyara.so]
Without the third argument the library is looked up in the XXYARA_LIBRARY environment variable, next to this
script, then in the system's library search path.
"""
import ctypes
import os
import sys


def load_library(explicit=None):
    name = {"nt": "xxyara.dll", "posix": "libxxyara.so"}.get(os.name, "libxxyara.dylib")
    if sys.platform == "darwin":
        name = "libxxyara.dylib"
    for candidate in (explicit, os.environ.get("XXYARA_LIBRARY"),
                      os.path.join(os.path.dirname(os.path.abspath(__file__)), name), name):
        if candidate and (os.path.isfile(candidate) or candidate == name):
            return ctypes.CDLL(candidate)
    raise OSError("xxyara shared library not found")


class Match(ctypes.Structure):
    _fields_ = [("offset", ctypes.c_size_t), ("length", ctypes.c_size_t), ("xor_key", ctypes.c_int16)]


RULE_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)
PATTERN_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)
MATCH_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(Match), ctypes.c_void_p)


class XXYara:
    def __init__(self, library):
        self.lib = library
        u8p, size = ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
        for name, args in {
            "yrx_compile": [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)],
            "yrx_rules_destroy": [ctypes.c_void_p],
            "yrx_scanner_create": [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            "yrx_scanner_destroy": [ctypes.c_void_p],
            "yrx_scanner_on_matching_rule": [ctypes.c_void_p, RULE_CALLBACK, ctypes.c_void_p],
            "yrx_scanner_scan_file": [ctypes.c_void_p, ctypes.c_char_p],
            "yrx_rule_identifier": [ctypes.c_void_p, ctypes.POINTER(u8p), ctypes.POINTER(size)],
            "yrx_rule_iter_patterns": [ctypes.c_void_p, PATTERN_CALLBACK, ctypes.c_void_p],
            "yrx_pattern_identifier": [ctypes.c_void_p, ctypes.POINTER(u8p), ctypes.POINTER(size)],
            "yrx_pattern_iter_matches": [ctypes.c_void_p, MATCH_CALLBACK, ctypes.c_void_p],
        }.items():
            function = getattr(library, name)
            function.argtypes = args
            function.restype = None if name.endswith("_destroy") else ctypes.c_int
        library.yrx_last_error.argtypes = []
        library.yrx_last_error.restype = ctypes.c_char_p

    def error(self):
        message = self.lib.yrx_last_error()
        return message.decode("utf-8", "replace") if message else "unknown error"

    def _name(self, function, handle):
        text, length = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
        if function(handle, ctypes.byref(text), ctypes.byref(length)) != 0:
            return None
        return ctypes.string_at(text, length.value).decode("utf-8")

    def scan_file(self, source, path):
        """Return [(rule, [(pattern, offset, length), ...]), ...] for every matching rule."""
        rules, scanner = ctypes.c_void_p(), ctypes.c_void_p()
        if self.lib.yrx_compile(source.encode("utf-8"), ctypes.byref(rules)) != 0:
            raise RuntimeError(self.error())
        found = []

        def on_match(match, _):
            found[-1][1].append((current_pattern[0], match.contents.offset, match.contents.length))

        def on_pattern(pattern, _):
            current_pattern[0] = self._name(self.lib.yrx_pattern_identifier, pattern)
            self.lib.yrx_pattern_iter_matches(pattern, match_callback, None)

        def on_rule(rule, _):
            found.append((self._name(self.lib.yrx_rule_identifier, rule), []))
            self.lib.yrx_rule_iter_patterns(rule, pattern_callback, None)

        current_pattern = [None]
        # Keep the ctypes callback objects alive while C code can call them.
        match_callback, pattern_callback = MATCH_CALLBACK(on_match), PATTERN_CALLBACK(on_pattern)
        rule_callback = RULE_CALLBACK(on_rule)
        try:
            if self.lib.yrx_scanner_create(rules, ctypes.byref(scanner)) != 0:
                raise RuntimeError(self.error())
            self.lib.yrx_scanner_on_matching_rule(scanner, rule_callback, None)
            if self.lib.yrx_scanner_scan_file(scanner, os.fsencode(path)) != 0:
                raise RuntimeError(self.error())
        finally:
            if scanner:
                self.lib.yrx_scanner_destroy(scanner)
            self.lib.yrx_rules_destroy(rules)
        return found


def main():
    if len(sys.argv) not in (3, 4):
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    engine = XXYara(load_library(sys.argv[3] if len(sys.argv) == 4 else None))
    with open(sys.argv[1], encoding="utf-8") as rules_file:
        source = rules_file.read()
    try:
        results = engine.scan_file(source, sys.argv[2])
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    for rule, matches in results:
        print(rule)
        for pattern, offset, length in matches:
            print(f"  {pattern} at {offset}, {length} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
