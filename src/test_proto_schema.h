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

#ifndef XXYARA_TEST_PROTO_SCHEMA_H
#define XXYARA_TEST_PROTO_SCHEMA_H

/* Pinned YARA-X 1.21.0 test module types and native output defaults.
 * Include after internal.h, vt_schema.h and yx_module_array_desc.
 * Shared values below are immutable schema/native defaults; never free them.
 * Optional proto2 fields absent from main() remain undefined. Proto3 scalar
 * fields retain their default values. Injected protobuf values are tracked
 * separately; this table describes native output only. */
static const yx_vt_field yx_tp_fields[] = {
    {"test_proto2.int32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.int64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.sint32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.sint64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.uint32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.uint64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.fixed32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.fixed64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.sfixed32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.sfixed64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.float_zero", YX_VT_FLOAT, 0, 0, false},
    {"test_proto2.double_zero", YX_VT_FLOAT, 0, 0, false},
    {"test_proto2.int32_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.int64_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.sint32_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.sint64_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.uint32_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.uint64_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.fixed32_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.fixed64_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.sfixed32_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.sfixed64_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.float_one", YX_VT_FLOAT, 0, 0, false},
    {"test_proto2.double_one", YX_VT_FLOAT, 0, 0, false},
    {"test_proto2.int32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.int64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.sint32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.sint64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.uint32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.uint64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.fixed32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.fixed64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.sfixed32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.sfixed64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto2.float_undef", YX_VT_FLOAT, 0, 0, false},
    {"test_proto2.double_undef", YX_VT_FLOAT, 0, 0, false},
    {"test_proto2.string_foo", YX_VT_STRING, 0, 0, false},
    {"test_proto2.string_bar", YX_VT_STRING, 0, 0, false},
    {"test_proto2.string_undef", YX_VT_STRING, 0, 0, false},
    {"test_proto2.bytes_foo", YX_VT_STRING, 0, 0, false},
    {"test_proto2.bytes_bar", YX_VT_STRING, 0, 0, false},
    {"test_proto2.bytes_raw", YX_VT_STRING, 0, 0, false},
    {"test_proto2.bytes_undef", YX_VT_STRING, 0, 0, false},
    {"test_proto2.enumeration", YX_VT_INT, 0, 0, false},
    {"test_proto2.nested", YX_VT_STRUCT, 0, 0, false},
    {"test_proto2.nested.nested_int32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.nested.nested_int64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto2.nested.nested_int32_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.nested.nested_int64_one", YX_VT_INT, 0, 0, false},
    {"test_proto2.nested.nested_bool", YX_VT_BOOL, 0, 0, false},
    {"test_proto2.nested.nested_string", YX_VT_STRING, 0, 0, false},
    {"test_proto2.nested.nested_array_int64", YX_VT_ARRAY, 0, 0, false},
    {"test_proto2.nested.nested_array_int64.value", YX_VT_INT, 1, 0, true},
    {"test_proto2.array_int64", YX_VT_ARRAY, 0, 0, false},
    {"test_proto2.array_int64.value", YX_VT_INT, 1, 0, true},
    {"test_proto2.array_float", YX_VT_ARRAY, 0, 0, false},
    {"test_proto2.array_float.value", YX_VT_FLOAT, 1, 0, true},
    {"test_proto2.array_bool", YX_VT_ARRAY, 0, 0, false},
    {"test_proto2.array_bool.value", YX_VT_BOOL, 1, 0, true},
    {"test_proto2.array_string", YX_VT_ARRAY, 0, 0, false},
    {"test_proto2.array_string.value", YX_VT_STRING, 1, 0, true},
    {"test_proto2.array_struct", YX_VT_ARRAY, 0, 0, false},
    {"test_proto2.array_struct.value", YX_VT_STRUCT, 1, 0, true},
    {"test_proto2.array_struct.nested_int32_zero", YX_VT_INT, 1, 0, false},
    {"test_proto2.array_struct.nested_int64_zero", YX_VT_INT, 1, 0, false},
    {"test_proto2.array_struct.nested_int32_one", YX_VT_INT, 1, 0, false},
    {"test_proto2.array_struct.nested_int64_one", YX_VT_INT, 1, 0, false},
    {"test_proto2.array_struct.nested_bool", YX_VT_BOOL, 1, 0, false},
    {"test_proto2.array_struct.nested_string", YX_VT_STRING, 1, 0, false},
    {"test_proto2.array_struct.nested_array_int64", YX_VT_ARRAY, 1, 0, false},
    {"test_proto2.array_struct.nested_array_int64.value", YX_VT_INT, 2, 0, true},
    {"test_proto2.map_string_struct", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_string_struct.value", YX_VT_STRUCT, 1, 1, true},
    {"test_proto2.map_string_struct.nested_int32_zero", YX_VT_INT, 1, 1, false},
    {"test_proto2.map_string_struct.nested_int64_zero", YX_VT_INT, 1, 1, false},
    {"test_proto2.map_string_struct.nested_int32_one", YX_VT_INT, 1, 1, false},
    {"test_proto2.map_string_struct.nested_int64_one", YX_VT_INT, 1, 1, false},
    {"test_proto2.map_string_struct.nested_bool", YX_VT_BOOL, 1, 1, false},
    {"test_proto2.map_string_struct.nested_string", YX_VT_STRING, 1, 1, false},
    {"test_proto2.map_string_struct.nested_array_int64", YX_VT_ARRAY, 1, 1, false},
    {"test_proto2.map_string_struct.nested_array_int64.value", YX_VT_INT, 2, 1, true},
    {"test_proto2.map_string_int64", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_string_int64.value", YX_VT_INT, 1, 1, true},
    {"test_proto2.map_string_string", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_string_string.value", YX_VT_STRING, 1, 1, true},
    {"test_proto2.map_string_bool", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_string_bool.value", YX_VT_BOOL, 1, 1, true},
    {"test_proto2.map_string_float", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_string_float.value", YX_VT_FLOAT, 1, 1, true},
    {"test_proto2.map_int64_struct", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_int64_struct.value", YX_VT_STRUCT, 1, 0, true},
    {"test_proto2.map_int64_struct.nested_int32_zero", YX_VT_INT, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_int64_zero", YX_VT_INT, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_int32_one", YX_VT_INT, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_int64_one", YX_VT_INT, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_bool", YX_VT_BOOL, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_string", YX_VT_STRING, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_array_int64", YX_VT_ARRAY, 1, 0, false},
    {"test_proto2.map_int64_struct.nested_array_int64.value", YX_VT_INT, 2, 0, true},
    {"test_proto2.map_int64_int64", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_int64_int64.value", YX_VT_INT, 1, 0, true},
    {"test_proto2.map_int64_string", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_int64_string.value", YX_VT_STRING, 1, 0, true},
    {"test_proto2.map_int64_bool", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_int64_bool.value", YX_VT_BOOL, 1, 0, true},
    {"test_proto2.map_int64_float", YX_VT_MAP, 0, 0, false},
    {"test_proto2.map_int64_float.value", YX_VT_FLOAT, 1, 0, true},
    {"test_proto2.timestamp", YX_VT_INT, 0, 0, false},
    {"test_proto2.bool_yara", YX_VT_BOOL, 0, 0, false},
    {"test_proto2.file_size", YX_VT_INT, 0, 0, false},
    {"test_proto2.requires_foo_and_bar", YX_VT_INT, 0, 0, false},
    {"test_proto2.deprecated", YX_VT_STRING, 0, 0, false},
    {"test_proto2.metadata", YX_VT_STRING, 0, 0, false},
    {"test_proto3.int32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.int64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.sint32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.sint64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.uint32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.uint64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.fixed32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.fixed64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.sfixed32_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.sfixed64_zero", YX_VT_INT, 0, 0, false},
    {"test_proto3.float_zero", YX_VT_FLOAT, 0, 0, false},
    {"test_proto3.int32_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.int64_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.sint32_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.sint64_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.uint32_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.uint64_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.fixed32_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.fixed64_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.sfixed32_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.sfixed64_one", YX_VT_INT, 0, 0, false},
    {"test_proto3.float_one", YX_VT_FLOAT, 0, 0, false},
    {"test_proto3.int32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.int64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.sint32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.sint64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.uint32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.uint64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.fixed32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.fixed64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.sfixed32_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.sfixed64_undef", YX_VT_INT, 0, 0, false},
    {"test_proto3.float_undef", YX_VT_FLOAT, 0, 0, false},
    {"test_proto3.bool_undef", YX_VT_BOOL, 0, 0, false},
    {"test_proto3.string_foo", YX_VT_STRING, 0, 0, false},
    {"test_proto3.string_bar", YX_VT_STRING, 0, 0, false},
    {"test_proto3.string_undef", YX_VT_STRING, 0, 0, false},
    {"test_proto3.bytes_foo", YX_VT_STRING, 0, 0, false},
    {"test_proto3.bytes_bar", YX_VT_STRING, 0, 0, false},
    {"test_proto3.bytes_undef", YX_VT_STRING, 0, 0, false},
    {"test_proto2.Enumeration", YX_VT_STRUCT, 0, 0, false},
    {"test_proto2.Enumeration.ITEM_0", YX_VT_INT, 0, 0, false},
    {"test_proto2.Enumeration.ITEM_1", YX_VT_INT, 0, 0, false},
    {"test_proto2.Enumeration.ITEM_2", YX_VT_INT, 0, 0, false},
    {"test_proto2.Enumeration.ITEM_3", YX_VT_INT, 0, 0, false},
    {"test_proto2.items", YX_VT_STRUCT, 0, 0, false},
    {"test_proto2.items.ITEM_4", YX_VT_INT, 0, 0, false},
    {"test_proto2.items.ITEM_5", YX_VT_INT, 0, 0, false},
    {"test_proto2.TopLevelEnumeration", YX_VT_STRUCT, 0, 0, false},
    {"test_proto2.TopLevelEnumeration.ITEM_0x1000", YX_VT_INT, 0, 0, false},
    {"test_proto2.TopLevelEnumeration.ITEM_0x2000", YX_VT_INT, 0, 0, false},
    {"test_proto2.NestedProto2.NestedEnumeration", YX_VT_STRUCT, 0, 0, false},
    {"test_proto2.NestedProto2.NestedEnumeration.ITEM_0", YX_VT_INT, 0, 0, false},
    {"test_proto2.NestedProto2.NestedEnumeration.ITEM_1", YX_VT_INT, 0, 0, false},
    {"test_proto2.INLINE_0x1000", YX_VT_INT, 0, 0, false},
    {"test_proto2.INLINE_0x2000", YX_VT_INT, 0, 0, false},
    {"test_proto2.NestedProto2", YX_VT_STRUCT, 0, 0, false},
};

typedef enum { YX_TP_UNDEFINED, YX_TP_CONSTANT, YX_TP_SCAN_SIZE, YX_TP_METADATA } yx_tp_native_kind;
typedef struct {
    const char *path;
    yx_vt_type type;
    yx_tp_native_kind kind;
    int64_t integer;
    double floating;
    const char *string;
    size_t length;
} yx_tp_native_field;

static const yx_tp_native_field yx_tp_native_fields[] = {
    {"test_proto2.int32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.int64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sint32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sint64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.uint32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.uint64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.fixed32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.fixed64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sfixed32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sfixed64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.float_zero", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.double_zero", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.int32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.int64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.sint32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.sint64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.uint32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.uint64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.fixed32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.fixed64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.sfixed32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.sfixed64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.float_one", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.double_one", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.int32_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.int64_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sint32_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sint64_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.uint32_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.uint64_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.fixed32_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.fixed64_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sfixed32_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.sfixed64_undef", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.float_undef", YX_VT_FLOAT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.double_undef", YX_VT_FLOAT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.string_foo", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto2.string_bar", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x62\x61\x72", 3},
    {"test_proto2.string_undef", YX_VT_STRING, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.bytes_foo", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto2.bytes_bar", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x62\x61\x72", 3},
    {"test_proto2.bytes_raw", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\xfc\x48\x83\xe4\xf0\xeb\x33\x5d\x8b\x45\x00\x48", 12},
    {"test_proto2.bytes_undef", YX_VT_STRING, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.enumeration", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.nested.nested_int32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.nested.nested_int64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.nested.nested_int32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.nested.nested_int64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.nested.nested_bool", YX_VT_BOOL, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.nested.nested_string", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto2.array_struct.nested_int32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.array_struct.nested_int64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.array_struct.nested_int32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.array_struct.nested_int64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.array_struct.nested_bool", YX_VT_BOOL, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.array_struct.nested_string", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto2.map_string_struct.nested_int32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.map_string_struct.nested_int64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.map_string_struct.nested_int32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.map_string_struct.nested_int64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.map_string_struct.nested_bool", YX_VT_BOOL, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.map_string_struct.nested_string", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto2.map_int64_struct.nested_int32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.map_int64_struct.nested_int64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.map_int64_struct.nested_int32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.map_int64_struct.nested_int64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto2.map_int64_struct.nested_bool", YX_VT_BOOL, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.map_int64_struct.nested_string", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto2.timestamp", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1748591440), 0.0, NULL, 0},
    {"test_proto2.bool_yara", YX_VT_BOOL, YX_TP_CONSTANT, INT64_C(1), 0.0, NULL, 0},
    {"test_proto2.file_size", YX_VT_INT, YX_TP_SCAN_SIZE, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.requires_foo_and_bar", YX_VT_INT, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.deprecated", YX_VT_STRING, YX_TP_UNDEFINED, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.metadata", YX_VT_STRING, YX_TP_METADATA, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.int32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.int64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sint32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sint64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.uint32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.uint64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.fixed32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.fixed64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sfixed32_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sfixed64_zero", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.float_zero", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.int32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.int64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.sint32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.sint64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.uint32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.uint64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.fixed32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.fixed64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.sfixed32_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.sfixed64_one", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.float_one", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(1), 1.0, NULL, 0},
    {"test_proto3.int32_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.int64_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sint32_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sint64_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.uint32_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.uint64_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.fixed32_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.fixed64_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sfixed32_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.sfixed64_undef", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.float_undef", YX_VT_FLOAT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.bool_undef", YX_VT_BOOL, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto3.string_foo", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto3.string_bar", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x62\x61\x72", 3},
    {"test_proto3.string_undef", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "", 0},
    {"test_proto3.bytes_foo", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x66\x6f\x6f", 3},
    {"test_proto3.bytes_bar", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "\x62\x61\x72", 3},
    {"test_proto3.bytes_undef", YX_VT_STRING, YX_TP_CONSTANT, INT64_C(0), 0.0, "", 0},
    {"test_proto2.Enumeration.ITEM_0", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.Enumeration.ITEM_1", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 0.0, NULL, 0},
    {"test_proto2.Enumeration.ITEM_2", YX_VT_INT, YX_TP_CONSTANT, INT64_C(140737488355327), 0.0, NULL, 0},
    {"test_proto2.Enumeration.ITEM_3", YX_VT_INT, YX_TP_CONSTANT, INT64_C(-1), 0.0, NULL, 0},
    {"test_proto2.items.ITEM_4", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.items.ITEM_5", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 0.0, NULL, 0},
    {"test_proto2.TopLevelEnumeration.ITEM_0x1000", YX_VT_INT, YX_TP_CONSTANT, INT64_C(4096), 0.0, NULL, 0},
    {"test_proto2.TopLevelEnumeration.ITEM_0x2000", YX_VT_INT, YX_TP_CONSTANT, INT64_C(8192), 0.0, NULL, 0},
    {"test_proto2.NestedProto2.NestedEnumeration.ITEM_0", YX_VT_INT, YX_TP_CONSTANT, INT64_C(0), 0.0, NULL, 0},
    {"test_proto2.NestedProto2.NestedEnumeration.ITEM_1", YX_VT_INT, YX_TP_CONSTANT, INT64_C(1), 0.0, NULL, 0},
    {"test_proto2.INLINE_0x1000", YX_VT_INT, YX_TP_CONSTANT, INT64_C(4096), 0.0, NULL, 0},
    {"test_proto2.INLINE_0x2000", YX_VT_INT, YX_TP_CONSTANT, INT64_C(8192), 0.0, NULL, 0},
};

static yx_global_scalar_value yx_tp_int_items[] = { {.integer=1}, {.integer=10}, {.integer=100} };
static yx_global_array yx_tp_int_array = {YX_GLOBAL_INT, yx_tp_int_items, 3};
static yx_global_scalar_value yx_tp_float_items[] = { {.floating=1.0}, {.floating=10.0}, {.floating=100.0} };
static yx_global_array yx_tp_float_array = {YX_GLOBAL_FLOAT, yx_tp_float_items, 3};
static yx_global_scalar_value yx_tp_bool_items[] = { {.boolean=false}, {.boolean=true} };
static yx_global_array yx_tp_bool_array = {YX_GLOBAL_BOOL, yx_tp_bool_items, 2};
static yx_global_scalar_value yx_tp_string_items[] = { {.string={"foo",3}}, {.string={"bar",3}}, {.string={"baz",3}} };
static yx_global_array yx_tp_string_array = {YX_GLOBAL_STR, yx_tp_string_items, 3};

static yx_global_field yx_tp_nested_fields_0[] = {
    {"nested_int32_zero", YX_GLOBAL_INT, {.integer=0}},
    {"nested_int64_zero", YX_GLOBAL_INT, {.integer=0}},
    {"nested_int32_one", YX_GLOBAL_INT, {.integer=1}},
    {"nested_int64_one", YX_GLOBAL_INT, {.integer=1}},
    {"nested_bool", YX_GLOBAL_BOOL, {.boolean=false}},
    {"nested_string", YX_GLOBAL_STR, {.string={"foo",3}}},
    {"nested_array_int64", YX_GLOBAL_ARRAY, {.array=&yx_tp_int_array}},
};
static yx_global_object yx_tp_nested_object_0 = {yx_tp_nested_fields_0, 7};

static yx_global_field yx_tp_nested_fields_1[] = {
    {"nested_int32_zero", YX_GLOBAL_INT, {.integer=0}},
    {"nested_int64_zero", YX_GLOBAL_INT, {.integer=0}},
    {"nested_int32_one", YX_GLOBAL_INT, {.integer=1}},
    {"nested_int64_one", YX_GLOBAL_INT, {.integer=1}},
    {"nested_bool", YX_GLOBAL_BOOL, {.boolean=true}},
    {"nested_string", YX_GLOBAL_STR, {.string={"foo",3}}},
    {"nested_array_int64", YX_GLOBAL_ARRAY, {.array=&yx_tp_int_array}},
};
static yx_global_object yx_tp_nested_object_1 = {yx_tp_nested_fields_1, 7};
static yx_global_scalar_value yx_tp_nested_items[] = { {.object=&yx_tp_nested_object_0}, {.object=&yx_tp_nested_object_1} };
static yx_global_array yx_tp_nested_array = {YX_GLOBAL_STRUCT, yx_tp_nested_items, 2};

static const yx_module_array_desc yx_tp_arrays[] = {
    {"test_proto2.nested.nested_array_int64", &yx_tp_int_array, 0},
    {"test_proto2.array_int64", &yx_tp_int_array, 0},
    {"test_proto2.array_float", &yx_tp_float_array, 0},
    {"test_proto2.array_bool", &yx_tp_bool_array, 0},
    {"test_proto2.array_string", &yx_tp_string_array, 0},
    {"test_proto2.array_struct", &yx_tp_nested_array, 0},
    {"test_proto2.array_struct.nested_array_int64", &yx_tp_int_array, 1},
    {"test_proto2.map_string_struct.nested_array_int64", &yx_tp_int_array, 1},
    {"test_proto2.map_int64_struct.nested_array_int64", &yx_tp_int_array, 1},
};

typedef struct {
    const char *path;
    yx_vt_type key_type, value_type;
    const char *string_key;
    int64_t integer_key;
    yx_global_scalar_value value;
    const yx_global_array *record_schema;
} yx_tp_native_map;

/* Every native test map has one entry. Map values remain typed even when
 * an injected output leaves the map empty. */
static const yx_tp_native_map yx_tp_maps[] = {
    {"test_proto2.map_string_struct", YX_VT_STRING, YX_VT_STRUCT, "foo", 0, {.object=&yx_tp_nested_object_0}, &yx_tp_nested_array},
    {"test_proto2.map_string_int64", YX_VT_STRING, YX_VT_INT, "one", 0, {.integer=1}, NULL},
    {"test_proto2.map_string_string", YX_VT_STRING, YX_VT_STRING, "foo", 0, {.string={"FOO",3}}, NULL},
    {"test_proto2.map_string_bool", YX_VT_STRING, YX_VT_BOOL, "foo", 0, {.boolean=true}, NULL},
    {"test_proto2.map_string_float", YX_VT_STRING, YX_VT_FLOAT, "one", 0, {.floating=1.0}, NULL},
    {"test_proto2.map_int64_struct", YX_VT_INT, YX_VT_STRUCT, NULL, 100, {.object=&yx_tp_nested_object_0}, &yx_tp_nested_array},
    {"test_proto2.map_int64_int64", YX_VT_INT, YX_VT_INT, NULL, 100, {.integer=1000}, NULL},
    {"test_proto2.map_int64_string", YX_VT_INT, YX_VT_STRING, NULL, 100, {.string={"one thousand",12}}, NULL},
    {"test_proto2.map_int64_bool", YX_VT_INT, YX_VT_BOOL, NULL, 100, {.boolean=true}, NULL},
    {"test_proto2.map_int64_float", YX_VT_INT, YX_VT_FLOAT, NULL, 100, {.floating=1000.0}, NULL},
};

/* Functions are implemented by the evaluator; the listed receiver is empty
 * for module functions and names the protobuf message for methods. */
typedef struct { const char *path, *receiver; yx_vt_type result; unsigned argc; yx_vt_type args[2]; bool may_be_undefined; } yx_tp_function;
static const yx_tp_function yx_tp_functions[] = {
    {"test_proto2.add", "", YX_VT_INT, 2, {YX_VT_INT, YX_VT_INT}, false},
    {"test_proto2.add", "", YX_VT_FLOAT, 2, {YX_VT_FLOAT, YX_VT_FLOAT}, false},
    {"test_proto2.uppercase", "", YX_VT_STRING, 1, {YX_VT_STRING}, false},
    {"test_proto2.nested.nested_func", "", YX_VT_BOOL, 0, {YX_VT_INT}, false},
    {"test_proto2.nested_method", "test_proto2.NestedProto2", YX_VT_BOOL, 0, {YX_VT_INT}, false},
    {"test_proto2.nested_method_with_arg", "test_proto2.NestedProto2", YX_VT_BOOL, 1, {YX_VT_STRING}, false},
    {"test_proto2.undef_i64", "", YX_VT_INT, 0, {YX_VT_INT}, true},
    {"test_proto2.head", "", YX_VT_STRING, 1, {YX_VT_INT}, true},
    {"test_proto2.get_foo", "", YX_VT_STRING, 0, {YX_VT_INT}, true},
    {"test_proto2.to_int", "", YX_VT_INT, 1, {YX_VT_STRING}, true},
};

#endif
