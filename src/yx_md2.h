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

#ifndef YX_MD2_H
#define YX_MD2_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t state[48];
    uint8_t checksum[16];
    uint8_t buffer[16];
    size_t count;
} yx_md2_context;

/* Permutation table S derived from the digits of pi (RFC 1319 Section 3.1) */
static const uint8_t yx_md2_pi_subst[256] = {
    41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
    98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
    30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
   190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
   169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
   128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
   255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
    79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
    69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
    27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
    85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
    44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
   106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
   120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
   242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
    49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20
};

static void yx_md2_transform_block(uint8_t state[48], const uint8_t block[16])
{
    for (size_t i = 0; i < 16; ++i) {
        state[16 + i] = block[i];
        state[32 + i] = block[i] ^ state[i];
    }
    uint8_t t = 0;
    for (size_t round = 0; round < 18; ++round) {
        for (size_t k = 0; k < 48; ++k) {
            t = state[k] ^ yx_md2_pi_subst[t];
            state[k] = t;
        }
        t = (uint8_t)((t + (uint8_t)round) & 0xFF);
    }
}

static void yx_md2_update_checksum(uint8_t checksum[16], const uint8_t block[16])
{
    uint8_t l = checksum[15];
    for (size_t i = 0; i < 16; ++i) {
        checksum[i] ^= yx_md2_pi_subst[block[i] ^ l];
        l = checksum[i];
    }
}

static void yx_md2_process_block(yx_md2_context *ctx, const uint8_t block[16])
{
    yx_md2_update_checksum(ctx->checksum, block);
    yx_md2_transform_block(ctx->state, block);
}

static void yx_md2_init(yx_md2_context *ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

static void yx_md2_update(yx_md2_context *ctx, const uint8_t *data, size_t size)
{
    if (!ctx || !data || !size) return;

    size_t buffer_used = ctx->count;
    ctx->count = (ctx->count + size) & 0x0F;

    if (buffer_used > 0) {
        size_t needed = 16 - buffer_used;
        if (size < needed) {
            memcpy(ctx->buffer + buffer_used, data, size);
            return;
        }
        memcpy(ctx->buffer + buffer_used, data, needed);
        yx_md2_process_block(ctx, ctx->buffer);
        data += needed;
        size -= needed;
    }

    while (size >= 16) {
        yx_md2_process_block(ctx, data);
        data += 16;
        size -= 16;
    }

    if (size > 0) {
        memcpy(ctx->buffer, data, size);
    }
}

static void yx_md2_final(yx_md2_context *ctx, uint8_t digest[16])
{
    if (!ctx || !digest) return;

    size_t pad_len = 16 - ctx->count;
    uint8_t pad[16];
    for (size_t i = 0; i < pad_len; ++i) {
        pad[i] = (uint8_t)pad_len;
    }
    yx_md2_update(ctx, pad, pad_len);

    /* Transform the final 16-byte checksum block (not fed into checksum itself) */
    yx_md2_transform_block(ctx->state, ctx->checksum);

    memcpy(digest, ctx->state, 16);
    memset(ctx, 0, sizeof(*ctx));
}

static void yx_md2(const uint8_t *data, size_t size, uint8_t digest[16])
{
    yx_md2_context ctx;
    yx_md2_init(&ctx);
    yx_md2_update(&ctx, data, size);
    yx_md2_final(&ctx, digest);
}

#ifdef __cplusplus
}
#endif

#endif /* YX_MD2_H */
