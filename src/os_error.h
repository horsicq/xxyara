/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef XXYARA_OS_ERROR_H
#define XXYARA_OS_ERROR_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

/* Keep Win32 error numbers distinct from the C runtime's errno values. */
static inline unsigned long yx_os_error_last(void)
{
#ifdef _WIN32
    DWORD error = GetLastError();
    return error ? error : ERROR_GEN_FAILURE;
#else
    return (unsigned long)(errno ? errno : EIO);
#endif
}

#ifdef _WIN32
/* The White_Space characters that Rust's str::trim_end removes. */
static inline int yx_os_error_is_space(wchar_t ch)
{
    return (ch >= 0x0009 && ch <= 0x000d) || ch == 0x0020 || ch == 0x0085 ||
           ch == 0x00a0 || ch == 0x1680 || (ch >= 0x2000 && ch <= 0x200a) ||
           ch == 0x2028 || ch == 0x2029 || ch == 0x202f || ch == 0x205f ||
           ch == 0x3000;
}
#endif

/* Mirrors the Display of Rust's std::io::Error for OS errors: on Windows the
 * text of sys::pal::windows::os::error_string followed by " (os error N)", where
 * N is the raw code printed as a signed 32-bit integer. */
static inline const char *yx_os_error_text(unsigned long error)
{
    static _Thread_local char text[8192];
#ifdef _WIN32
    wchar_t wide[2048];
    int32_t code = (int32_t)(uint32_t)error;
    int32_t number = code;
    HMODULE module = NULL;
    DWORD flags = 0;
    DWORD length;
    int used = 0;
    /* NTSTATUS values encoded as HRESULTs are formatted from NTDLL. */
    if (((uint32_t)number & 0x10000000u) != 0) {
        module = GetModuleHandleW(L"NTDLL.DLL");
        if (module) {
            number = (int32_t)((uint32_t)number ^ 0x10000000u);
            flags = FORMAT_MESSAGE_FROM_HMODULE;
        }
    }
    length = FormatMessageW(flags | FORMAT_MESSAGE_FROM_SYSTEM |
                            FORMAT_MESSAGE_IGNORE_INSERTS,
                            module, (DWORD)(uint32_t)number, 0, wide,
                            (DWORD)(sizeof(wide) / sizeof(wide[0])), NULL);
    if (length == 0) {
        DWORD format_error = GetLastError();
        used = snprintf(text, sizeof(text),
                        "OS Error %ld (FormatMessageW() returned error %ld)",
                        (long)number, (long)(int32_t)format_error);
    } else {
        while (length && yx_os_error_is_space(wide[length - 1])) --length;
        if (length)
            used = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide,
                                       (int)length, text,
                                       (int)sizeof(text) - 64, NULL, NULL);
        if (length && !used)
            used = snprintf(text, sizeof(text),
                            "OS Error %ld (FormatMessageW() returned invalid UTF-16)",
                            (long)number);
    }
    if (used < 0) used = 0;
    snprintf(text + used, sizeof(text) - (size_t)used,
             " (os error %ld)", (long)code);
#else
    snprintf(text, sizeof(text), "%s (os error %lu)",
             strerror((int)error), error);
#endif
    return text;
}

#endif
