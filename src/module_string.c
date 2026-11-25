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

#include "module_string.h"

#include "xxfclib/strings/xx_string.h"

#include <limits.h>

bool yx_string_length(const uint8_t *bytes, size_t size, int64_t *out)
{
    if (!out || (!bytes && size) || size > INT64_MAX) return false;
    *out = (int64_t)size;
    return true;
}

/* Rust's i64::from_str_radix; a base outside 2..36 is undefined. */
bool yx_string_to_int_base(const uint8_t *bytes, size_t size, int64_t base, int64_t *out)
{
    if (base < 2 || base > 36) return false;
    return xx_str_to_i64_radix((const char *)bytes, size, (unsigned)base, out);
}

bool yx_string_to_int(const uint8_t *bytes, size_t size, int64_t *out)
{
    return yx_string_to_int_base(bytes, size, 10, out);
}
