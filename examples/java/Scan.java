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

// xxyara example in Java 22+: the YARA-X C API of xxyara through the Foreign Function & Memory API
// (no JNI code, no libraries).
// usage: java --enable-native-access=ALL-UNNAMED Scan.java <xxyara.dll | libxxyara.so> <rules.yar> <file>
import java.lang.foreign.AddressLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Scan {
    private static final Linker LINKER = Linker.nativeLinker();
    private static final ValueLayout.OfLong SIZE_T = ValueLayout.JAVA_LONG;
    private static SymbolLookup library;
    private static MethodHandle ruleIdentifier, ruleIterPatterns, patternIdentifier, patternIterMatches;
    private static MemorySegment onPatternStub, onMatchStub;
    private static final List<String> output = new ArrayList<>();
    private static String currentPattern;

    private static MethodHandle function(String name, FunctionDescriptor descriptor) {
        return LINKER.downcallHandle(library.find(name).orElseThrow(), descriptor);
    }

    private static MemorySegment upcall(String method, FunctionDescriptor descriptor, Arena arena) throws Exception {
        MethodType type = MethodType.methodType(void.class, MemorySegment.class, MemorySegment.class);
        return LINKER.upcallStub(MethodHandles.lookup().findStatic(Scan.class, method, type), descriptor, arena);
    }

    private static String name(MethodHandle getter, MemorySegment handle) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment length = arena.allocate(SIZE_T);
            if ((int) getter.invokeExact(handle, text, length) != 0) {
                return null;
            }
            long size = length.get(SIZE_T, 0);
            byte[] bytes = text.get(ValueLayout.ADDRESS, 0).reinterpret(size).toArray(ValueLayout.JAVA_BYTE);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    // Callbacks run inside native code: an exception must not escape them.
    private static void onMatch(MemorySegment match, MemorySegment userData) {
        MemorySegment fields = match.reinterpret(24);  // struct YRX_MATCH { size_t offset; size_t length; int16_t xor_key; }
        output.add("  " + currentPattern + " at " + fields.get(SIZE_T, 0) + ", " + fields.get(SIZE_T, 8) + " bytes");
    }

    private static void onPattern(MemorySegment pattern, MemorySegment userData) {
        try {
            currentPattern = name(patternIdentifier, pattern);
            if (currentPattern != null) {
                int status = (int) patternIterMatches.invokeExact(pattern, onMatchStub, MemorySegment.NULL);
            }
        } catch (Throwable error) {
            output.add("error: " + error);
        }
    }

    private static void onRule(MemorySegment rule, MemorySegment userData) {
        try {
            String identifier = name(ruleIdentifier, rule);
            if (identifier != null) {
                output.add(identifier);
                int status = (int) ruleIterPatterns.invokeExact(rule, onPatternStub, MemorySegment.NULL);
            }
        } catch (Throwable error) {
            output.add("error: " + error);
        }
    }

    public static void main(String[] args) throws Throwable {
        if (args.length != 3) {
            System.err.println("usage: java --enable-native-access=ALL-UNNAMED Scan.java <library> <rules.yar> <file>");
            System.exit(2);
        }
        try (Arena arena = Arena.ofConfined()) {
            library = SymbolLookup.libraryLookup(Path.of(args[0]), arena);
            ValueLayout.OfInt result = ValueLayout.JAVA_INT;
            AddressLayout address = ValueLayout.ADDRESS;
            MethodHandle compile = function("yrx_compile", FunctionDescriptor.of(result, address, address));
            MethodHandle rulesDestroy = function("yrx_rules_destroy", FunctionDescriptor.ofVoid(address));
            MethodHandle scannerCreate = function("yrx_scanner_create", FunctionDescriptor.of(result, address, address));
            MethodHandle scannerDestroy = function("yrx_scanner_destroy", FunctionDescriptor.ofVoid(address));
            MethodHandle onMatchingRule = function("yrx_scanner_on_matching_rule",
                    FunctionDescriptor.of(result, address, address, address));
            MethodHandle scanFile = function("yrx_scanner_scan_file", FunctionDescriptor.of(result, address, address));
            MethodHandle lastError = function("yrx_last_error", FunctionDescriptor.of(address));
            ruleIdentifier = function("yrx_rule_identifier", FunctionDescriptor.of(result, address, address, address));
            ruleIterPatterns = function("yrx_rule_iter_patterns", FunctionDescriptor.of(result, address, address, address));
            patternIdentifier = function("yrx_pattern_identifier", FunctionDescriptor.of(result, address, address, address));
            patternIterMatches = function("yrx_pattern_iter_matches",
                    FunctionDescriptor.of(result, address, address, address));
            FunctionDescriptor callback = FunctionDescriptor.ofVoid(address, address);
            MemorySegment onRuleStub = upcall("onRule", callback, arena);
            onPatternStub = upcall("onPattern", callback, arena);
            onMatchStub = upcall("onMatch", callback, arena);

            String source = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
            MemorySegment rules = arena.allocate(address);
            if ((int) compile.invokeExact(arena.allocateFrom(source), rules) != 0) {
                MemorySegment message = (MemorySegment) lastError.invokeExact();
                System.err.println(message.reinterpret(Long.MAX_VALUE).getString(0));
                System.exit(1);
            }
            MemorySegment scanner = arena.allocate(address);
            int status = (int) scannerCreate.invokeExact(rules.get(address, 0), scanner);
            if (status == 0) {
                status = (int) onMatchingRule.invokeExact(scanner.get(address, 0), onRuleStub, MemorySegment.NULL);
                status = (int) scanFile.invokeExact(scanner.get(address, 0), arena.allocateFrom(args[2]));
                if (status != 0) {
                    MemorySegment message = (MemorySegment) lastError.invokeExact();
                    System.err.println(message.reinterpret(Long.MAX_VALUE).getString(0));
                }
                scannerDestroy.invokeExact(scanner.get(address, 0));
            }
            rulesDestroy.invokeExact(rules.get(address, 0));
            for (String line : output) {
                System.out.println(line);
            }
            System.exit(status == 0 ? 0 : 1);
        }
    }
}
