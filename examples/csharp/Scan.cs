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

// xxyara example in C#: P/Invoke over the shared library xxyara.dll (the YARA-X C API).
// Use it in any .NET 6+ console project (copy xxyara.dll next to the executable), or run
// examples/powershell/scan.ps1, which compiles this file with Add-Type.
// usage: Scan <rules.yar> <file>
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace XXYara.Example
{
    public static class Native
    {
        private const string Library = "xxyara";

        [StructLayout(LayoutKind.Sequential)]
        public struct Match
        {
            public UIntPtr Offset;
            public UIntPtr Length;
            public short XorKey;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void RuleCallback(IntPtr rule, IntPtr userData);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void PatternCallback(IntPtr pattern, IntPtr userData);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void MatchCallback(ref Match match, IntPtr userData);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_compile(byte[] source, out IntPtr rules);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern void yrx_rules_destroy(IntPtr rules);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_scanner_create(IntPtr rules, out IntPtr scanner);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern void yrx_scanner_destroy(IntPtr scanner);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_scanner_on_matching_rule(IntPtr scanner, RuleCallback callback, IntPtr userData);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_scanner_scan_file(IntPtr scanner, byte[] path);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_rule_identifier(IntPtr rule, out IntPtr text, out UIntPtr length);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_rule_iter_patterns(IntPtr rule, PatternCallback callback, IntPtr userData);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_pattern_identifier(IntPtr pattern, out IntPtr text, out UIntPtr length);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern int yrx_pattern_iter_matches(IntPtr pattern, MatchCallback callback, IntPtr userData);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr yrx_last_error();
    }

    public static class Program
    {
        private static byte[] CString(string text)
        {
            return Encoding.UTF8.GetBytes(text + "\0");
        }

        private static string Utf8(IntPtr text, UIntPtr length)
        {
            byte[] bytes = new byte[(int)length.ToUInt64()];
            Marshal.Copy(text, bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(bytes);
        }

        private static string LastError()
        {
            IntPtr message = Native.yrx_last_error();
            return message == IntPtr.Zero ? "unknown error" : Marshal.PtrToStringUTF8(message);
        }

        public static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("usage: Scan <rules.yar> <file>");
                return 2;
            }
            IntPtr rules;
            if (Native.yrx_compile(CString(File.ReadAllText(args[0])), out rules) != 0)
            {
                Console.Error.WriteLine(LastError());
                return 1;
            }
            List<string> output = new List<string>();
            string currentPattern = null;
            Native.MatchCallback onMatch = delegate (ref Native.Match match, IntPtr userData)
            {
                output.Add("  " + currentPattern + " at " + match.Offset + ", " + match.Length + " bytes");
            };
            Native.PatternCallback onPattern = delegate (IntPtr pattern, IntPtr userData)
            {
                IntPtr text;
                UIntPtr length;
                if (Native.yrx_pattern_identifier(pattern, out text, out length) != 0)
                    return;
                currentPattern = Utf8(text, length);
                Native.yrx_pattern_iter_matches(pattern, onMatch, IntPtr.Zero);
            };
            Native.RuleCallback onRule = delegate (IntPtr rule, IntPtr userData)
            {
                IntPtr text;
                UIntPtr length;
                if (Native.yrx_rule_identifier(rule, out text, out length) != 0)
                    return;
                output.Add(Utf8(text, length));
                Native.yrx_rule_iter_patterns(rule, onPattern, IntPtr.Zero);
            };
            int status = 1;
            IntPtr scanner;
            if (Native.yrx_scanner_create(rules, out scanner) == 0)
            {
                Native.yrx_scanner_on_matching_rule(scanner, onRule, IntPtr.Zero);
                if (Native.yrx_scanner_scan_file(scanner, CString(args[1])) == 0)
                    status = 0;
                else
                    Console.Error.WriteLine(LastError());
                Native.yrx_scanner_destroy(scanner);
            }
            else
            {
                Console.Error.WriteLine(LastError());
            }
            Native.yrx_rules_destroy(rules);
            // The delegates must stay alive while native code may call them.
            GC.KeepAlive(onRule);
            GC.KeepAlive(onPattern);
            GC.KeepAlive(onMatch);
            foreach (string line in output)
                Console.WriteLine(line);
            return status;
        }
    }
}
