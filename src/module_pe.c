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

#include "module_pe.h"
#include "internal.h"

#include "xxfclib/formats/executable/pe/xx_pe_yx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The YARA-X PE parser first consumes all 64 bytes of IMAGE_DOS_HEADER,
 * then seeks to e_lfanew and consumes IMAGE_NT_SIGNATURE (4 bytes) and
 * IMAGE_FILE_HEADER (20 bytes). Optional-header and section-table parse
 * failures are ignored when producing pe.is_pe. Do not reject odd values in
 * the COFF header or require e_lfanew to follow the DOS header: the reference
 * parser accepts both. */
bool yx_pe_is_pe(const uint8_t *data, size_t size)
{
    uint32_t pe_offset;
    const uint8_t *pe;
    if (!data || size < 64 || data[0] != 'M' || data[1] != 'Z') return false;
    pe_offset = (uint32_t)data[60] | ((uint32_t)data[61] << 8) | ((uint32_t)data[62] << 16) | ((uint32_t)data[63] << 24);
    if ((uint64_t)pe_offset > size || size - (size_t)pe_offset < 24) return false;
    pe = data + (size_t)pe_offset;
    return pe[0] == 'P' && pe[1] == 'E' && pe[2] == 0 && pe[3] == 0;
}

typedef struct {
    const char *name;
    unsigned source; /* 0: COFF, 1: optional, 2: 32-bit optional only */
    unsigned width;
    unsigned offset32;
    unsigned offset64;
} yx_pe_field_desc;

static const yx_pe_field_desc yx_pe_fields[] = {
    {"machine", 0, 2, 4, 4},
    {"number_of_sections", 0, 2, 6, 6},
    {"timestamp", 0, 4, 8, 8},
    {"pointer_to_symbol_table", 0, 4, 12, 12},
    {"number_of_symbols", 0, 4, 16, 16},
    {"size_of_optional_header", 0, 2, 20, 20},
    {"characteristics", 0, 2, 22, 22},
    {"opthdr_magic", 1, 2, 0, 0},
    {"linker_version.major", 1, 1, 2, 2},
    {"linker_version.minor", 1, 1, 3, 3},
    {"size_of_code", 1, 4, 4, 4},
    {"size_of_initialized_data", 1, 4, 8, 8},
    {"size_of_uninitialized_data", 1, 4, 12, 12},
    {"entry_point_raw", 1, 4, 16, 16},
    {"base_of_code", 1, 4, 20, 20},
    {"base_of_data", 2, 4, 24, 24},
    {"image_base", 1, 0, 28, 24},
    {"section_alignment", 1, 4, 32, 32},
    {"file_alignment", 1, 4, 36, 36},
    {"os_version.major", 1, 2, 40, 40},
    {"os_version.minor", 1, 2, 42, 42},
    {"image_version.major", 1, 2, 44, 44},
    {"image_version.minor", 1, 2, 46, 46},
    {"subsystem_version.major", 1, 2, 48, 48},
    {"subsystem_version.minor", 1, 2, 50, 50},
    {"win32_version_value", 1, 4, 52, 52},
    {"size_of_image", 1, 4, 56, 56},
    {"size_of_headers", 1, 4, 60, 60},
    {"checksum", 1, 4, 64, 64},
    {"subsystem", 1, 2, 68, 68},
    {"dll_characteristics", 1, 2, 70, 70},
    {"size_of_stack_reserve", 1, 0, 72, 72},
    {"size_of_stack_commit", 1, 0, 76, 80},
    {"size_of_heap_reserve", 1, 0, 80, 88},
    {"size_of_heap_commit", 1, 0, 84, 96},
    {"loader_flags", 1, 4, 88, 104},
    {"number_of_rva_and_sizes", 1, 4, 92, 108},
};

typedef struct {
    const char *name;
    uint64_t value;
} yx_pe_constant_desc;

static const yx_pe_constant_desc yx_pe_constants[] = {
    {"MACHINE_UNKNOWN", 0x0000},
    {"MACHINE_ALPHA", 0x0184},
    {"MACHINE_ALPHA64", 0x0284},
    {"MACHINE_AM33", 0x01d3},
    {"MACHINE_AMD64", 0x8664},
    {"MACHINE_ARM", 0x01c0},
    {"MACHINE_ARM64", 0xaa64},
    {"MACHINE_ARM64EC", 0xa641},
    {"MACHINE_ARM64X", 0xa64e},
    {"MACHINE_ARMNT", 0x01c4},
    {"MACHINE_AXP64", 0x0284},
    {"MACHINE_EBC", 0x0ebc},
    {"MACHINE_I386", 0x014c},
    {"MACHINE_IA64", 0x0200},
    {"MACHINE_LOONGARCH32", 0x6232},
    {"MACHINE_LOONGARCH64", 0x6264},
    {"MACHINE_M32R", 0x9041},
    {"MACHINE_MIPS16", 0x0266},
    {"MACHINE_MIPSFPU", 0x0366},
    {"MACHINE_MIPSFPU16", 0x0466},
    {"MACHINE_POWERPC", 0x01f0},
    {"MACHINE_POWERPCFP", 0x01f1},
    {"MACHINE_R3000BE", 0x0160},
    {"MACHINE_R3000", 0x0162},
    {"MACHINE_R4000", 0x0166},
    {"MACHINE_R10000", 0x0168},
    {"MACHINE_RISCV32", 0x5032},
    {"MACHINE_RISCV64", 0x5064},
    {"MACHINE_RISCV128", 0x5128},
    {"MACHINE_SH3", 0x01a2},
    {"MACHINE_SH3DSP", 0x01a3},
    {"MACHINE_SH4", 0x01a6},
    {"MACHINE_SH5", 0x01a8},
    {"MACHINE_THUMB", 0x01c2},
    {"MACHINE_WCEMIPSV2", 0x0169},
    {"SUBSYSTEM_UNKNOWN", 0},
    {"SUBSYSTEM_NATIVE", 1},
    {"SUBSYSTEM_WINDOWS_GUI", 2},
    {"SUBSYSTEM_WINDOWS_CUI", 3},
    {"SUBSYSTEM_OS2_CUI", 5},
    {"SUBSYSTEM_POSIX_CUI", 7},
    {"SUBSYSTEM_NATIVE_WINDOWS", 8},
    {"SUBSYSTEM_WINDOWS_CE_GUI", 9},
    {"SUBSYSTEM_EFI_APPLICATION", 10},
    {"SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 11},
    {"SUBSYSTEM_EFI_RUNTIME_DRIVER", 12},
    {"SUBSYSTEM_EFI_ROM_IMAGE", 13},
    {"SUBSYSTEM_XBOX", 14},
    {"SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16},
    {"RELOCS_STRIPPED", 0x0001},
    {"EXECUTABLE_IMAGE", 0x0002},
    {"LINE_NUMS_STRIPPED", 0x0004},
    {"LOCAL_SYMS_STRIPPED", 0x0008},
    {"AGGRESIVE_WS_TRIM", 0x0010},
    {"LARGE_ADDRESS_AWARE", 0x0020},
    {"BYTES_REVERSED_LO", 0x0080},
    {"MACHINE_32BIT", 0x0100},
    {"DEBUG_STRIPPED", 0x0200},
    {"REMOVABLE_RUN_FROM_SWAP", 0x0400},
    {"NET_RUN_FROM_SWAP", 0x0800},
    {"SYSTEM", 0x1000},
    {"DLL", 0x2000},
    {"UP_SYSTEM_ONLY", 0x4000},
    {"BYTES_REVERSED_HI", 0x8000},
    {"HIGH_ENTROPY_VA", 0x0020},
    {"DYNAMIC_BASE", 0x0040},
    {"FORCE_INTEGRITY", 0x0080},
    {"NX_COMPAT", 0x0100},
    {"NO_ISOLATION", 0x0200},
    {"NO_SEH", 0x0400},
    {"NO_BIND", 0x0800},
    {"APPCONTAINER", 0x1000},
    {"WDM_DRIVER", 0x2000},
    {"GUARD_CF", 0x4000},
    {"TERMINAL_SERVER_AWARE", 0x8000},
    {"IMAGE_NT_OPTIONAL_HDR32_MAGIC", 0x10b},
    {"IMAGE_NT_OPTIONAL_HDR64_MAGIC", 0x20b},
    {"IMAGE_ROM_OPTIONAL_HDR_MAGIC", 0x107},
    {"IMPORT_STANDARD", 1},
    {"IMPORT_DELAYED", 2},
    {"IMPORT_ANY", 3},
    {"RESOURCE_TYPE_CURSOR", 1},
    {"RESOURCE_TYPE_BITMAP", 2},
    {"RESOURCE_TYPE_ICON", 3},
    {"RESOURCE_TYPE_MENU", 4},
    {"RESOURCE_TYPE_DIALOG", 5},
    {"RESOURCE_TYPE_STRING", 6},
    {"RESOURCE_TYPE_FONTDIR", 7},
    {"RESOURCE_TYPE_FONT", 8},
    {"RESOURCE_TYPE_ACCELERATOR", 9},
    {"RESOURCE_TYPE_RCDATA", 10},
    {"RESOURCE_TYPE_MESSAGETABLE", 11},
    {"RESOURCE_TYPE_GROUP_CURSOR", 12},
    {"RESOURCE_TYPE_GROUP_ICON", 14},
    {"RESOURCE_TYPE_VERSION", 16},
    {"RESOURCE_TYPE_DLGINCLUDE", 17},
    {"RESOURCE_TYPE_PLUGPLAY", 19},
    {"RESOURCE_TYPE_VXD", 20},
    {"RESOURCE_TYPE_ANICURSOR", 21},
    {"RESOURCE_TYPE_ANIICON", 22},
    {"RESOURCE_TYPE_HTML", 23},
    {"RESOURCE_TYPE_MANIFEST", 24},
    {"IMAGE_DIRECTORY_ENTRY_EXPORT", 0},
    {"IMAGE_DIRECTORY_ENTRY_IMPORT", 1},
    {"IMAGE_DIRECTORY_ENTRY_RESOURCE", 2},
    {"IMAGE_DIRECTORY_ENTRY_EXCEPTION", 3},
    {"IMAGE_DIRECTORY_ENTRY_SECURITY", 4},
    {"IMAGE_DIRECTORY_ENTRY_BASERELOC", 5},
    {"IMAGE_DIRECTORY_ENTRY_DEBUG", 6},
    {"IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 7},
    {"IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", 7},
    {"IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 8},
    {"IMAGE_DIRECTORY_ENTRY_TLS", 9},
    {"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 10},
    {"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 11},
    {"IMAGE_DIRECTORY_ENTRY_IAT", 12},
    {"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 13},
    {"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 14},
    {"SECTION_NO_PAD", 0x00000008},
    {"SECTION_CNT_CODE", 0x00000020},
    {"SECTION_CNT_INITIALIZED_DATA", 0x00000040},
    {"SECTION_CNT_UNINITIALIZED_DATA", 0x00000080},
    {"SECTION_LNK_OTHER", 0x00000100},
    {"SECTION_LNK_INFO", 0x00000200},
    {"SECTION_LNK_REMOVE", 0x00000800},
    {"SECTION_LNK_COMDAT", 0x00001000},
    {"SECTION_NO_DEFER_SPEC_EXC", 0x00004000},
    {"SECTION_GPREL", 0x00008000},
    {"SECTION_ALIGN_1BYTES", 0x00100000},
    {"SECTION_ALIGN_2BYTES", 0x00200000},
    {"SECTION_ALIGN_4BYTES", 0x00300000},
    {"SECTION_ALIGN_8BYTES", 0x00400000},
    {"SECTION_ALIGN_16BYTES", 0x00500000},
    {"SECTION_ALIGN_32BYTES", 0x00600000},
    {"SECTION_ALIGN_64BYTES", 0x00700000},
    {"SECTION_ALIGN_128BYTES", 0x00800000},
    {"SECTION_ALIGN_256BYTES", 0x00900000},
    {"SECTION_ALIGN_512BYTES", 0x00a00000},
    {"SECTION_ALIGN_1024BYTES", 0x00b00000},
    {"SECTION_ALIGN_2048BYTES", 0x00c00000},
    {"SECTION_ALIGN_4096BYTES", 0x00d00000},
    {"SECTION_ALIGN_8192BYTES", 0x00e00000},
    {"SECTION_ALIGN_MASK", 0x00f00000},
    {"SECTION_LNK_NRELOC_OVFL", 0x01000000},
    {"SECTION_MEM_DISCARDABLE", 0x02000000},
    {"SECTION_MEM_NOT_CACHED", 0x04000000},
    {"SECTION_MEM_NOT_PAGED", 0x08000000},
    {"SECTION_MEM_SHARED", 0x10000000},
    {"SECTION_MEM_EXECUTE", 0x20000000},
    {"SECTION_MEM_READ", 0x40000000},
    {"SECTION_MEM_WRITE", 0x80000000},
    {"SECTION_SCALE_INDEX", 0x00000001},
};

static uint64_t yx_pe_read(const uint8_t *data, size_t offset, unsigned width)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) value |= (uint64_t)data[offset + i] << (8 * i);
    return value;
}

static const yx_pe_field_desc *yx_pe_find_field(const char *member)
{
    if (!member) return NULL;
    for (size_t i = 0; i < sizeof(yx_pe_fields) / sizeof(yx_pe_fields[0]); ++i)
        if (strcmp(member, yx_pe_fields[i].name) == 0) return &yx_pe_fields[i];
    return NULL;
}

bool yx_pe_data_directory_count(const uint8_t *data, size_t size, uint64_t *count)
{
    uint64_t declared;
    size_t optional, start;
    if (!count) return false;
    *count = 0;
    if (!yx_pe_field(data, size, "number_of_rva_and_sizes", &declared)) return true;
    optional = (size_t)yx_pe_read(data, 60, 4) + 24;
    if (size - optional < 2) return true;
    start = optional + (yx_pe_read(data, optional, 2) == 0x20b ? 112u : 96u);
    if (declared > 16) declared = 16;
    if (start <= size && declared <= (size - start) / 8) *count = declared;
    return true;
}

bool yx_pe_data_directory_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value)
{
    uint64_t count;
    size_t optional, start;
    if (!member || !value || (strcmp(member, "virtual_address") != 0 && strcmp(member, "size") != 0) || !yx_pe_data_directory_count(data, size, &count) || index >= count)
        return false;
    optional = (size_t)yx_pe_read(data, 60, 4) + 24;
    start = optional + (yx_pe_read(data, optional, 2) == 0x20b ? 112u : 96u);
    *value = yx_pe_read(data, start + (size_t)index * 8 + (strcmp(member, "size") == 0 ? 4u : 0u), 4);
    return true;
}

bool yx_pe_rich_tool_count(const uint8_t *data, size_t size, uint64_t *count)
{
    return xx_pe_yx_rich_tool_count(data, size, count);
}

bool yx_pe_rich_tool_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value)
{
    return xx_pe_yx_rich_tool_field(data, size, index, member, value);
}

bool yx_pe_rich_clear_data(const uint8_t *data, size_t size, uint8_t **bytes, size_t *length)
{
    return xx_pe_yx_rich_clear_data(data, size, bytes, length);
}

static size_t yx_pe_sections(const uint8_t *data, size_t size, size_t pe_offset, size_t *sections_offset)
{
    size_t offset = pe_offset + 24;
    size_t count;
    uint64_t optional_size = yx_pe_read(data, pe_offset + 20, 2);
    if (optional_size > size - offset) return 0;
    offset += (size_t)optional_size;
    count = (size_t)yx_pe_read(data, pe_offset + 6, 2);
    if (count > 96) count = 96;
    if (count > (size - offset) / 40) count = (size - offset) / 40;
    if (sections_offset) *sections_offset = offset;
    return count;
}

typedef struct {
    const char *name;
    unsigned offset;
    unsigned width;
} yx_pe_section_field_desc;

static const yx_pe_section_field_desc yx_pe_section_fields[] = {
    {"virtual_size", 8, 4},           {"virtual_address", 12, 4},        {"raw_data_size", 16, 4},
    {"raw_data_offset", 20, 4},       {"pointer_to_relocations", 24, 4}, {"pointer_to_line_numbers", 28, 4},
    {"number_of_relocations", 32, 2}, {"number_of_line_numbers", 34, 2}, {"characteristics", 36, 4},
};

static bool yx_pe_section_at(const uint8_t *data, size_t size, uint64_t index, size_t *offset)
{
    size_t pe_offset, sections_offset, count;
    if (!offset || !yx_pe_is_pe(data, size)) return false;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    count = yx_pe_sections(data, size, pe_offset, &sections_offset);
    if (index >= count) return false;
    *offset = sections_offset + (size_t)index * 40;
    return true;
}

bool yx_pe_section_count(const uint8_t *data, size_t size, uint64_t *count)
{
    size_t pe_offset;
    if (!count) return false;
    *count = 0;
    if (!yx_pe_is_pe(data, size)) return true;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    *count = yx_pe_sections(data, size, pe_offset, NULL);
    return true;
}

bool yx_pe_section_field_supported(const char *member)
{
    if (!member) return false;
    for (size_t i = 0; i < sizeof(yx_pe_section_fields) / sizeof(yx_pe_section_fields[0]); ++i)
        if (strcmp(member, yx_pe_section_fields[i].name) == 0) return true;
    return false;
}

bool yx_pe_section_field(const uint8_t *data, size_t size, uint64_t index, const char *member, uint64_t *value)
{
    size_t offset;
    if (!value || !member || !yx_pe_section_at(data, size, index, &offset)) return false;
    for (size_t i = 0; i < sizeof(yx_pe_section_fields) / sizeof(yx_pe_section_fields[0]); ++i)
        if (strcmp(member, yx_pe_section_fields[i].name) == 0) {
            *value = yx_pe_read(data, offset + yx_pe_section_fields[i].offset, yx_pe_section_fields[i].width);
            return true;
        }
    return false;
}

bool yx_pe_section_string_field_supported(const char *member)
{
    return member && (strcmp(member, "name") == 0 || strcmp(member, "full_name") == 0);
}

bool yx_pe_section_string_field(const uint8_t *data, size_t size, uint64_t index, const char *member, const uint8_t **bytes, size_t *length)
{
    size_t offset, name_length = 8;
    const uint8_t *name;
    if (!bytes || !length || !yx_pe_section_string_field_supported(member) || !yx_pe_section_at(data, size, index, &offset)) return false;
    name = data + offset;
    while (name_length && name[name_length - 1] == 0) --name_length;
    *bytes = name;
    *length = name_length;
    if (strcmp(member, "name") == 0 || name_length < 2 || name[0] != '/') return true;

    /* GNU long section names use a decimal offset from the start of the COFF
       string table. YARA-X also returns the raw `/digits` name separately. */
    size_t at = 1;
    uint64_t string_offset = 0;
    if (name[at] == '+') ++at;
    if (at == name_length) return true;
    for (; at < name_length; ++at) {
        if (name[at] < '0' || name[at] > '9') return true;
        string_offset = string_offset * 10 + name[at] - '0';
        if (string_offset > UINT32_MAX) return true;
    }
    size_t pe_offset = (size_t)yx_pe_read(data, 60, 4);
    uint64_t symbol_offset = yx_pe_read(data, pe_offset + 12, 4);
    uint64_t symbols = yx_pe_read(data, pe_offset + 16, 4);
    uint64_t string_table_offset = symbol_offset + symbols * 18;
    if (string_table_offset > UINT32_MAX) string_table_offset = UINT32_MAX;
    if (string_table_offset > size || string_offset > size - (size_t)string_table_offset) return true;
    size_t resolved_offset = (size_t)string_table_offset + (size_t)string_offset;
    const uint8_t *resolved = data + resolved_offset;
    size_t resolved_length = 0;
    while (resolved_length < size - resolved_offset && resolved[resolved_length] != 0) ++resolved_length;
    *bytes = resolved;
    *length = resolved_length;
    return true;
}

bool yx_pe_field_supported(const char *member)
{
    return member &&
           (strcmp(member, "is_pe") == 0 || strcmp(member, "entry_point") == 0 || strcmp(member, "overlay.offset") == 0 || strcmp(member, "overlay.size") == 0 ||
            strcmp(member, "rich_signature.offset") == 0 || strcmp(member, "rich_signature.length") == 0 || strcmp(member, "rich_signature.key") == 0 ||
            strcmp(member, "number_of_exports") == 0 || strcmp(member, "export_timestamp") == 0 || strcmp(member, "number_of_resources") == 0 ||
            strcmp(member, "number_of_version_infos") == 0 || strcmp(member, "resource_timestamp") == 0 || strcmp(member, "resource_version.major") == 0 ||
            strcmp(member, "resource_version.minor") == 0 || strcmp(member, "number_of_imports") == 0 || strcmp(member, "number_of_imported_functions") == 0 ||
            strcmp(member, "number_of_delayed_imports") == 0 || strcmp(member, "number_of_delayed_imported_functions") == 0 || yx_pe_find_field(member) != NULL);
}

bool yx_pe_rva_to_offset(const uint8_t *data, size_t size, uint64_t rva, uint64_t *value)
{
    return xx_pe_yx_rva_to_offset(data, size, rva, value);
}

bool yx_pe_offset_to_rva(const uint8_t *data, size_t size, uint64_t offset, uint64_t *value)
{
    return xx_pe_yx_offset_to_rva(data, size, offset, value);
}

bool yx_pe_section_index_name(const uint8_t *data, size_t size, const char *name, size_t name_length, uint64_t *value)
{
    size_t pe_offset, sections_offset, count;
    if (!value || !name || !yx_pe_is_pe(data, size)) return false;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    count = yx_pe_sections(data, size, pe_offset, &sections_offset);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t *raw_name = data + sections_offset + i * 40;
        size_t length = 8;
        while (length && raw_name[length - 1] == 0) --length;
        if (name_length == length && memcmp(name, raw_name, length) == 0) {
            *value = i;
            return true;
        }
    }
    return false;
}

bool yx_pe_section_index_offset(const uint8_t *data, size_t size, uint64_t offset, uint64_t *value)
{
    size_t pe_offset, sections_offset, count;
    if (!value || offset > UINT32_MAX || !yx_pe_is_pe(data, size)) return false;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    count = yx_pe_sections(data, size, pe_offset, &sections_offset);
    for (size_t i = 0; i < count; ++i) {
        size_t section = sections_offset + i * 40;
        uint32_t raw_size = (uint32_t)yx_pe_read(data, section + 16, 4);
        uint32_t raw_offset = (uint32_t)yx_pe_read(data, section + 20, 4);
        if (offset >= raw_offset && offset - raw_offset < raw_size) {
            *value = i;
            return true;
        }
    }
    return false;
}

bool yx_pe_overlay(const uint8_t *data, size_t size, uint64_t *offset, uint64_t *length)
{
    size_t pe_offset, sections_offset, count;
    uint64_t highest_end = 0;
    if (!offset || !length || !yx_pe_is_pe(data, size)) return false;
    *offset = 0;
    *length = 0;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    count = yx_pe_sections(data, size, pe_offset, &sections_offset);
    for (size_t i = 0; i < count; ++i) {
        size_t section = sections_offset + i * 40;
        uint64_t raw_offset = yx_pe_read(data, section + 20, 4);
        uint64_t raw_size = yx_pe_read(data, section + 16, 4);
        uint64_t end = raw_offset + raw_size;
        if (end > highest_end) highest_end = end;
    }
    if (count && highest_end < size) {
        *offset = highest_end;
        *length = (uint64_t)size - highest_end;
    }
    return true;
}

static bool yx_pe_offset_for_rva(const uint8_t *data, size_t size, uint32_t rva, size_t *offset)
{
    uint64_t candidate;
    if (!yx_pe_rva_to_offset(data, size, rva, &candidate) || candidate > size) return false;
    *offset = (size_t)candidate;
    return true;
}

/* Deadline-aware poll thunk handed to the xxfclib walkers. */
static bool yx_pe_deadline_poll(void *opaque)
{
    return yx_scan_deadline_poll((yx_scan_deadline *)opaque);
}

static bool yx_pe_visit_resources_with_deadline(const uint8_t *data, size_t size, yx_pe_resource_directory *result, yx_pe_resource_visitor visitor, void *opaque,
                                                yx_scan_deadline *deadline)
{
    return xx_pe_yx_visit_resources(data, size, result, (xx_pe_yx_resource_visitor)visitor, opaque, deadline ? yx_pe_deadline_poll : NULL, deadline);
}

bool yx_pe_visit_resources(const uint8_t *data, size_t size, yx_pe_resource_directory *result, yx_pe_resource_visitor visitor, void *opaque)
{
    return yx_pe_visit_resources_with_deadline(data, size, result, visitor, opaque, NULL);
}

bool yx_pe_visit_version_info(const uint8_t *data, size_t size, yx_pe_version_visitor visitor, void *opaque)
{
    return xx_pe_yx_visit_version_info(data, size, (xx_pe_yx_version_visitor)visitor, opaque, NULL, NULL);
}

typedef struct {
    const uint8_t *data;
    size_t size;
    uint64_t versions;
} yx_pe_resource_count_context;

static void yx_pe_count_version(void *opaque, const yx_pe_resource *resource)
{
    yx_pe_resource_count_context *ctx = opaque;
    if (resource->type.kind == YX_PE_RESOURCE_NUMERIC && resource->type.value == 16 && resource->has_offset && resource->offset < ctx->size)
        ctx->versions += xx_pe_yx_version_walk_at(ctx->data, ctx->size, resource->offset, NULL, NULL, NULL, NULL);
}

static bool yx_pe_resource_counts(const uint8_t *data, size_t size, uint64_t *resources, uint64_t *version_infos)
{
    yx_pe_resource_directory directory;
    yx_pe_resource_count_context ctx = {data, size, 0};
    if (!resources || !version_infos || !yx_pe_visit_resources(data, size, &directory, yx_pe_count_version, &ctx)) return false;
    *resources = directory.count;
    *version_infos = ctx.versions;
    return true;
}

bool yx_pe_string_field_supported(const char *member)
{
    return member && (strcmp(member, "dll_name") == 0 || strcmp(member, "rich_signature.raw_data") == 0 || strcmp(member, "pdb_path") == 0);
}

static bool yx_pe_debug_pdb_path(const uint8_t *data, size_t size, const uint8_t **bytes, size_t *length)
{
    size_t pe_offset, optional_offset, directory_offset, debug_offset;
    size_t directory_size;
    uint16_t magic;
    uint32_t debug_rva;
    if (!yx_pe_is_pe(data, size)) return false;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    optional_offset = pe_offset + 24;
    if (size - optional_offset < 2) return false;
    magic = (uint16_t)yx_pe_read(data, optional_offset, 2);
    directory_offset = optional_offset + (magic == 0x20b ? 112u : 96u);
    if (directory_offset > size || size - directory_offset < 7u * 8u) return false;
    directory_offset += 6u * 8u;
    debug_rva = (uint32_t)yx_pe_read(data, directory_offset, 4);
    directory_size = (size_t)yx_pe_read(data, directory_offset + 4, 4);
    if (!yx_pe_offset_for_rva(data, size, debug_rva, &debug_offset)) return false;
    if (directory_size > size - debug_offset) directory_size = size - debug_offset;

    for (size_t pos = 0; directory_size - pos >= 28; pos += 28) {
        size_t entry = debug_offset + pos;
        uint32_t rva, raw;
        uint64_t mapped;
        size_t codeview_offset, prefix, path_length = 0;
        if (yx_pe_read(data, entry + 12, 4) != 2) continue;
        rva = (uint32_t)yx_pe_read(data, entry + 20, 4);
        raw = (uint32_t)yx_pe_read(data, entry + 24, 4);
        codeview_offset = rva && yx_pe_rva_to_offset(data, size, rva, &mapped) ? (size_t)mapped : (size_t)raw;
        if (!codeview_offset || codeview_offset > size || size - codeview_offset < 4) continue;

        if (memcmp(data + codeview_offset, "RSDS", 4) == 0) prefix = 24;
        else if (memcmp(data + codeview_offset, "NB10", 4) == 0) prefix = 16;
        else if (memcmp(data + codeview_offset, "MTOC", 4) == 0) prefix = 20;
        else continue;
        if (size - codeview_offset < prefix) continue;
        codeview_offset += prefix;
        while (path_length < size - codeview_offset && data[codeview_offset + path_length] != 0) ++path_length;
        *bytes = data + codeview_offset;
        *length = path_length;
        return true;
    }
    return false;
}

bool yx_pe_string_field(const uint8_t *data, size_t size, const char *member, const uint8_t **bytes, size_t *length)
{
    if (!bytes || !length || !yx_pe_string_field_supported(member)) return false;
    *bytes = NULL;
    *length = 0;
    if (strcmp(member, "rich_signature.raw_data") == 0) {
        xx_pe_yx_rich_info info;
        if (!xx_pe_yx_rich_read(data, size, &info)) return false;
        *bytes = data + info.offset;
        *length = info.length;
        return true;
    }
    if (strcmp(member, "dll_name") == 0) return xx_pe_yx_export_dll_name(data, size, bytes, length);
    return yx_pe_debug_pdb_path(data, size, bytes, length);
}

static bool yx_pe_visit_exports_with_deadline(const uint8_t *data, size_t size, yx_pe_export_visitor visitor, void *opaque, yx_scan_deadline *deadline)
{
    return xx_pe_yx_visit_exports(data, size, (xx_pe_yx_export_visitor)visitor, opaque, deadline ? yx_pe_deadline_poll : NULL, deadline);
}

bool yx_pe_visit_exports(const uint8_t *data, size_t size, yx_pe_export_visitor visitor, void *opaque)
{
    return yx_pe_visit_exports_with_deadline(data, size, visitor, opaque, NULL);
}

struct yx_pe_scan_cache {
    const uint8_t *data;
    size_t size;
    yx_pe_export *exports;
    size_t export_count;
    size_t export_capacity;
    bool exports_built;
    bool exports_ok;
    yx_pe_resource *resources;
    size_t resource_count;
    size_t resource_capacity;
    bool resources_built;
    bool resources_ok;
    yx_pe_version_entry *versions;
    size_t version_count;
    size_t version_capacity;
    uint64_t version_info_count;
    bool versions_built;
    bool versions_ok;
};

void yx_pe_scan_cache_destroy(yx_pe_scan_cache *cache)
{
    if (!cache) return;
    for (size_t i = 0; i < cache->version_count; ++i) free(cache->versions[i].key);
    free(cache->versions);
    free(cache->resources);
    free(cache->exports);
    free(cache);
}

static yx_pe_scan_cache *yx_pe_scan_cache_get(yx_pe_scan_cache **slot, const uint8_t *data, size_t size)
{
    yx_pe_scan_cache *cache;
    if (!slot) return NULL;
    cache = *slot;
    if (cache && (cache->data != data || cache->size != size)) {
        yx_pe_scan_cache_destroy(cache);
        cache = *slot = NULL;
    }
    if (!cache) {
        cache = calloc(1, sizeof(*cache));
        if (!cache) return NULL;
        cache->data = data;
        cache->size = size;
        *slot = cache;
    }
    return cache;
}

static void *yx_pe_scan_cache_grow(void *items, size_t *capacity, size_t count, size_t item_size)
{
    size_t grown_capacity;
    void *grown;
    if (count < *capacity) return items;
    if (count == SIZE_MAX || count + 1 > SIZE_MAX / item_size) return NULL;
    grown_capacity = *capacity && *capacity <= SIZE_MAX / 2 ? *capacity * 2 : 16;
    if (grown_capacity < count + 1) grown_capacity = count + 1;
    if (grown_capacity > SIZE_MAX / item_size) grown_capacity = count + 1;
    grown = realloc(items, grown_capacity * item_size);
    if (grown) *capacity = grown_capacity;
    return grown;
}

typedef struct {
    yx_pe_scan_cache *cache;
    bool failed;
} yx_pe_scan_cache_build;

static void yx_pe_scan_cache_export_visit(void *opaque, const yx_pe_export *entry)
{
    yx_pe_scan_cache_build *build = opaque;
    yx_pe_scan_cache *cache = build->cache;
    yx_pe_export *grown;
    if (build->failed) return;
    grown = yx_pe_scan_cache_grow(cache->exports, &cache->export_capacity, cache->export_count, sizeof(*grown));
    if (!grown) {
        build->failed = true;
        return;
    }
    cache->exports = grown;
    cache->exports[cache->export_count++] = *entry;
}

static bool yx_pe_scan_cache_build_exports(yx_pe_scan_cache *cache, yx_scan_deadline *deadline)
{
    if (!cache->exports_built) {
        yx_pe_scan_cache_build build = {cache, false};
        cache->exports_built = true;
        cache->exports_ok = yx_pe_visit_exports_with_deadline(cache->data, cache->size, yx_pe_scan_cache_export_visit, &build, deadline) && !build.failed;
    }
    return cache->exports_ok;
}

const yx_pe_export *yx_pe_scan_cache_export(yx_pe_scan_cache **slot, const uint8_t *data, size_t size, uint64_t index, yx_scan_deadline *deadline)
{
    yx_pe_scan_cache *cache = yx_pe_scan_cache_get(slot, data, size);
    if (!cache || !yx_pe_scan_cache_build_exports(cache, deadline) || index >= cache->export_count) return NULL;
    return &cache->exports[(size_t)index];
}

static void yx_pe_scan_cache_resource_visit(void *opaque, const yx_pe_resource *resource)
{
    yx_pe_scan_cache_build *build = opaque;
    yx_pe_scan_cache *cache = build->cache;
    yx_pe_resource *grown;
    if (build->failed) return;
    grown = yx_pe_scan_cache_grow(cache->resources, &cache->resource_capacity, cache->resource_count, sizeof(*grown));
    if (!grown) {
        build->failed = true;
        return;
    }
    cache->resources = grown;
    cache->resources[cache->resource_count++] = *resource;
}

static bool yx_pe_scan_cache_build_resources(yx_pe_scan_cache *cache, yx_scan_deadline *deadline)
{
    if (!cache->resources_built) {
        yx_pe_resource_directory directory;
        yx_pe_scan_cache_build build = {cache, false};
        cache->resources_built = true;
        cache->resources_ok =
            xx_pe_yx_visit_resources(cache->data, cache->size, &directory, yx_pe_scan_cache_resource_visit, &build, deadline ? yx_pe_deadline_poll : NULL, deadline) &&
            !build.failed;
    }
    return cache->resources_ok;
}

const yx_pe_resource *yx_pe_scan_cache_resource(yx_pe_scan_cache **slot, const uint8_t *data, size_t size, uint64_t index, yx_scan_deadline *deadline)
{
    yx_pe_scan_cache *cache = yx_pe_scan_cache_get(slot, data, size);
    if (!cache || !yx_pe_scan_cache_build_resources(cache, deadline) || index >= cache->resource_count) return NULL;
    return &cache->resources[(size_t)index];
}

static void yx_pe_scan_cache_version_visit(void *opaque, const char *key, size_t key_length, const char *value, size_t value_length)
{
    yx_pe_scan_cache_build *build = opaque;
    yx_pe_scan_cache *cache = build->cache;
    yx_pe_version_entry *grown, *entry;
    char *strings;
    if (build->failed) return;
    if (value_length > SIZE_MAX - 2 || key_length > SIZE_MAX - value_length - 2) {
        build->failed = true;
        return;
    }
    grown = yx_pe_scan_cache_grow(cache->versions, &cache->version_capacity, cache->version_count, sizeof(*grown));
    if (!grown) {
        build->failed = true;
        return;
    }
    cache->versions = grown;
    strings = malloc(key_length + value_length + 2);
    if (!strings) {
        build->failed = true;
        return;
    }
    entry = &cache->versions[cache->version_count++];
    entry->key = strings;
    entry->key_length = key_length;
    entry->value = strings + key_length + 1;
    entry->value_length = value_length;
    memcpy(entry->key, key, key_length);
    entry->key[key_length] = '\0';
    memcpy(entry->value, value, value_length);
    entry->value[value_length] = '\0';
}

static bool yx_pe_scan_cache_build_versions(yx_pe_scan_cache *cache, yx_scan_deadline *deadline)
{
    if (!cache->versions_built) {
        yx_pe_scan_cache_build build = {cache, false};
        cache->versions_built = true;
        if (!yx_pe_scan_cache_build_resources(cache, deadline)) return false;
        for (size_t i = 0; i < cache->resource_count; ++i) {
            const yx_pe_resource *resource = &cache->resources[i];
            if (yx_scan_deadline_poll(deadline)) return false;
            if (resource->type.kind == YX_PE_RESOURCE_NUMERIC && resource->type.value == 16 && resource->has_offset && resource->offset < cache->size)
                cache->version_info_count += xx_pe_yx_version_walk_at(cache->data, cache->size, resource->offset, yx_pe_scan_cache_version_visit, &build,
                                                                      deadline ? yx_pe_deadline_poll : NULL, deadline);
            if (build.failed || yx_scan_deadline_reached(deadline)) return false;
        }
        cache->versions_ok = true;
    }
    return cache->versions_ok;
}

const yx_pe_version_entry *yx_pe_scan_cache_version(yx_pe_scan_cache **slot, const uint8_t *data, size_t size, uint64_t index, const char *key, size_t key_length,
                                                    yx_scan_deadline *deadline)
{
    const yx_pe_version_entry *result = NULL;
    yx_pe_scan_cache *cache = yx_pe_scan_cache_get(slot, data, size);
    if (!cache || !yx_pe_scan_cache_build_versions(cache, deadline)) return NULL;
    if (!key) return index < cache->version_count ? &cache->versions[(size_t)index] : NULL;
    /* The map retains the last value for duplicate keys; the list above
     * retains every record in parser order. */
    for (size_t i = 0; i < cache->version_count; ++i) {
        const yx_pe_version_entry *entry = &cache->versions[i];
        if (yx_scan_deadline_poll(deadline)) return NULL;
        if (entry->key_length == key_length && memcmp(entry->key, key, key_length) == 0) result = entry;
    }
    return result;
}

bool yx_pe_scan_cache_count(yx_pe_scan_cache **slot, const uint8_t *data, size_t size, const char *member, uint64_t *value, yx_scan_deadline *deadline)
{
    yx_pe_scan_cache *cache;
    if (!member || !value) return false;
    /* Export count is already bounded and cheap: retain lazy name parsing
     * until an indexed export is actually requested. */
    if (strcmp(member, "number_of_exports") == 0) return yx_pe_field(data, size, member, value);
    if (strcmp(member, "number_of_resources") != 0 && strcmp(member, "number_of_version_infos") != 0) return false;
    cache = yx_pe_scan_cache_get(slot, data, size);
    if (!cache || !yx_pe_scan_cache_build_resources(cache, deadline)) return false;
    if (strcmp(member, "number_of_resources") == 0) {
        *value = cache->resource_count;
        return true;
    }
    if (!yx_pe_scan_cache_build_versions(cache, deadline)) return false;
    /* Use the parser's count, which can differ from emitted callbacks for
     * a malformed partial version resource. */
    *value = cache->version_info_count;
    return true;
}

bool yx_pe_scan_cache_visit_versions(yx_pe_scan_cache **slot, const uint8_t *data, size_t size, yx_pe_version_visitor visitor, void *opaque, yx_scan_deadline *deadline)
{
    yx_pe_scan_cache *cache = yx_pe_scan_cache_get(slot, data, size);
    if (!cache || !yx_pe_scan_cache_build_versions(cache, deadline)) return false;
    for (size_t i = 0; visitor && i < cache->version_count; ++i) {
        const yx_pe_version_entry *entry = &cache->versions[i];
        if (yx_scan_deadline_poll(deadline)) return false;
        visitor(opaque, entry->key, entry->key_length, entry->value, entry->value_length);
    }
    return true;
}

bool yx_pe_exports(const uint8_t *data, size_t size, const char *name, size_t name_length, bool by_ordinal, uint64_t ordinal, bool *found, uint64_t *index)
{
    return xx_pe_yx_exports(data, size, name, name_length, by_ordinal, ordinal, found, index);
}

bool yx_pe_calculate_checksum(const uint8_t *data, size_t size, uint64_t *value)
{
    return xx_pe_yx_calculate_checksum(data, size, value);
}

bool yx_pe_field(const uint8_t *data, size_t size, const char *member, uint64_t *value)
{
    const yx_pe_field_desc *field;
    size_t pe_offset, optional_offset, offset;
    uint16_t magic = 0;
    bool is_64bit, optional_valid;
    unsigned width;
    if (!value || !member) return false;
    if (strcmp(member, "rich_signature.offset") == 0 || strcmp(member, "rich_signature.length") == 0 || strcmp(member, "rich_signature.key") == 0) {
        xx_pe_yx_rich_info info;
        if (!xx_pe_yx_rich_read(data, size, &info)) return false;
        *value = strcmp(member, "rich_signature.offset") == 0 ? info.offset : strcmp(member, "rich_signature.length") == 0 ? info.length : info.key;
        return true;
    }
    if (strcmp(member, "is_pe") == 0) {
        *value = yx_pe_is_pe(data, size);
        return true;
    }
    if (strcmp(member, "entry_point") == 0) {
        uint64_t rva;
        if (!yx_pe_field(data, size, "entry_point_raw", &rva)) return false;
        return yx_pe_rva_to_offset(data, size, rva, value);
    }
    if (strcmp(member, "overlay.offset") == 0 || strcmp(member, "overlay.size") == 0) {
        uint64_t offset, length;
        if (!yx_pe_overlay(data, size, &offset, &length)) return false;
        *value = strcmp(member, "overlay.offset") == 0 ? offset : length;
        return true;
    }
    if (strcmp(member, "number_of_exports") == 0 || strcmp(member, "export_timestamp") == 0) {
        bool present;
        uint64_t function_count, timestamp;
        if (!yx_pe_is_pe(data, size)) return false;
        if (!xx_pe_yx_export_info(data, size, &present, &function_count, &timestamp)) return false;
        if (strcmp(member, "export_timestamp") == 0 && !present) return false;
        *value = strcmp(member, "number_of_exports") == 0 ? function_count : timestamp;
        return true;
    }
    if (strcmp(member, "number_of_resources") == 0 || strcmp(member, "number_of_version_infos") == 0) {
        uint64_t resources, version_infos;
        if (!yx_pe_resource_counts(data, size, &resources, &version_infos)) return false;
        *value = strcmp(member, "number_of_resources") == 0 ? resources : version_infos;
        return true;
    }
    if (strcmp(member, "resource_timestamp") == 0 || strcmp(member, "resource_version.major") == 0 || strcmp(member, "resource_version.minor") == 0) {
        yx_pe_resource_directory directory;
        if (!yx_pe_visit_resources(data, size, &directory, NULL, NULL) || !directory.present) return false;
        if (strcmp(member, "resource_timestamp") == 0) *value = directory.timestamp;
        else if (strcmp(member, "resource_version.major") == 0) *value = directory.major_version;
        else *value = directory.minor_version;
        return true;
    }
    if (strcmp(member, "number_of_imports") == 0 || strcmp(member, "number_of_imported_functions") == 0 || strcmp(member, "number_of_delayed_imports") == 0 ||
        strcmp(member, "number_of_delayed_imported_functions") == 0) {
        yx_pe_import_stats stats;
        if (!yx_pe_get_import_stats(data, size, &stats)) return false;
        if (strcmp(member, "number_of_imports") == 0) *value = stats.standard_libraries;
        else if (strcmp(member, "number_of_imported_functions") == 0) *value = stats.standard_functions;
        else if (strcmp(member, "number_of_delayed_imports") == 0) *value = stats.delayed_libraries;
        else *value = stats.delayed_functions;
        return true;
    }
    field = yx_pe_find_field(member);
    if (!field || !yx_pe_is_pe(data, size)) return false;
    pe_offset = (size_t)yx_pe_read(data, 60, 4);
    if (strcmp(member, "number_of_sections") == 0) {
        *value = yx_pe_sections(data, size, pe_offset, NULL);
        return true;
    }
    optional_offset = pe_offset + 24;
    if (size - optional_offset >= 2) magic = (uint16_t)yx_pe_read(data, optional_offset, 2);
    is_64bit = magic == 0x20b;
    optional_valid = size - optional_offset >= (is_64bit ? 112u : 96u);
    if (field->source == 2 && (!optional_valid || is_64bit)) return false;
    if (field->source == 1 && !optional_valid) {
        *value = 0;
        return true;
    }
    offset = field->source == 0 ? pe_offset : optional_offset;
    offset += is_64bit ? field->offset64 : field->offset32;
    width = field->width ? field->width : (is_64bit ? 8u : 4u);
    if (offset > size || width > size - offset) return false;
    *value = yx_pe_read(data, offset, width);
    return true;
}

bool yx_pe_constant(const char *member, uint64_t *value)
{
    /* Every constant name starts with an upper-case letter; field names
     * (pe.is_pe, ...) do not, so they skip the table scan. */
    if (!member || member[0] < 'A' || member[0] > 'Z') return false;
    for (size_t i = 0; i < sizeof(yx_pe_constants) / sizeof(yx_pe_constants[0]); ++i)
        if (strcmp(member, yx_pe_constants[i].name) == 0) {
            if (value) *value = yx_pe_constants[i].value;
            return true;
        }
    return false;
}

bool yx_pe_function_supported(const char *member)
{
    return member &&
           (strcmp(member, "is_32bit") == 0 || strcmp(member, "is_64bit") == 0 || strcmp(member, "is_dll") == 0 || strcmp(member, "calculate_checksum") == 0 ||
            strcmp(member, "rich_signature.toolid") == 0 || strcmp(member, "rich_signature.version") == 0 || strcmp(member, "exports") == 0 ||
            strcmp(member, "exports_index") == 0 || strcmp(member, "imports") == 0 || strcmp(member, "import_rva") == 0 || strcmp(member, "delayed_import_rva") == 0 ||
            strcmp(member, "imphash") == 0 || strcmp(member, "rva_to_offset") == 0 || strcmp(member, "offset_to_rva") == 0 || strcmp(member, "section_index") == 0);
}

bool yx_pe_function(const uint8_t *data, size_t size, const char *member, uint64_t *value)
{
    uint64_t field;
    if (!value || !yx_pe_function_supported(member) || strcmp(member, "rva_to_offset") == 0 || strcmp(member, "offset_to_rva") == 0 ||
        strcmp(member, "section_index") == 0 || strcmp(member, "calculate_checksum") == 0 || strcmp(member, "rich_signature.toolid") == 0 ||
        strcmp(member, "rich_signature.version") == 0 || strcmp(member, "exports") == 0 || strcmp(member, "exports_index") == 0 || strcmp(member, "imports") == 0 ||
        strcmp(member, "import_rva") == 0 || strcmp(member, "delayed_import_rva") == 0 || strcmp(member, "imphash") == 0)
        return false;
    if (strcmp(member, "is_dll") == 0) {
        if (!yx_pe_field(data, size, "characteristics", &field)) return false;
        *value = (field & 0x2000) != 0;
    } else {
        if (!yx_pe_field(data, size, "opthdr_magic", &field)) return false;
        *value = field == (strcmp(member, "is_64bit") == 0 ? 0x20bu : 0x10bu);
    }
    return true;
}

static uint8_t yx_pe_ascii_lower(uint8_t ch)
{
    return ch >= 'A' && ch <= 'Z' ? (uint8_t)(ch + 'a' - 'A') : ch;
}

static bool yx_pe_ascii_equal(const uint8_t *a, size_t a_length, const char *b, size_t b_length)
{
    if (!b || a_length != b_length) return false;
    for (size_t i = 0; i < a_length; ++i)
        if (yx_pe_ascii_lower(a[i]) != yx_pe_ascii_lower((uint8_t)b[i])) return false;
    return true;
}

void yx_pe_visit_imports(const uint8_t *data, size_t size, unsigned flags, yx_pe_import_visitor visitor, void *opaque)
{
    xx_pe_yx_visit_imports(data, size, flags, (xx_pe_yx_import_visitor)visitor, opaque);
}

void yx_pe_visit_import_descriptors(const uint8_t *data, size_t size, unsigned flags, yx_pe_import_descriptor_visitor visitor, void *opaque)
{
    xx_pe_yx_visit_import_descriptors(data, size, flags, (xx_pe_yx_import_descriptor_visitor)visitor, opaque);
}

typedef struct {
    uint64_t requested_library;
    uint64_t requested_function;
    size_t previous_descriptor;
    uint64_t library_index;
    uint64_t functions;
    bool seen_descriptor;
    const uint8_t *library;
    size_t library_length;
    yx_pe_import_function *function;
    bool found_function;
} yx_pe_indexed_import_context;

static void yx_pe_indexed_import_visit(void *opaque, size_t descriptor, const uint8_t *dll, size_t dll_length, const uint8_t *name, size_t name_length, bool by_ordinal,
                                       uint16_t ordinal, uint32_t rva)
{
    yx_pe_indexed_import_context *context = opaque;
    if (!context->seen_descriptor || context->previous_descriptor != descriptor) {
        if (context->seen_descriptor) ++context->library_index;
        context->seen_descriptor = true;
        context->previous_descriptor = descriptor;
    }
    if (context->library_index != context->requested_library) return;
    context->library = dll;
    context->library_length = dll_length;
    if (context->function && context->functions == context->requested_function) {
        char *copy = malloc(name_length + 1);
        if (copy) {
            memcpy(copy, name, name_length);
            copy[name_length] = 0;
            context->function->name = copy;
            context->function->name_length = name_length;
            context->function->has_ordinal = by_ordinal;
            context->function->ordinal = ordinal;
            context->function->rva = rva;
            context->found_function = true;
        }
    }
    ++context->functions;
}

bool yx_pe_import_detail(const uint8_t *data, size_t size, bool delayed, uint64_t index, const uint8_t **library, size_t *library_length, uint64_t *function_count)
{
    yx_pe_indexed_import_context context = {0};
    if (!library || !library_length || !function_count) return false;
    context.requested_library = index;
    yx_pe_visit_import_descriptors(data, size, delayed ? 2u : 1u, yx_pe_indexed_import_visit, &context);
    if (!context.library) return false;
    *library = context.library;
    *library_length = context.library_length;
    *function_count = context.functions;
    return true;
}

bool yx_pe_import_function_detail(const uint8_t *data, size_t size, bool delayed, uint64_t library_index, uint64_t function_index, yx_pe_import_function *function)
{
    yx_pe_indexed_import_context context = {0};
    if (!function) return false;
    memset(function, 0, sizeof(*function));
    context.requested_library = library_index;
    context.requested_function = function_index;
    context.function = function;
    yx_pe_visit_import_descriptors(data, size, delayed ? 2u : 1u, yx_pe_indexed_import_visit, &context);
    return context.found_function;
}

bool yx_pe_get_import_stats(const uint8_t *data, size_t size, yx_pe_import_stats *out)
{
    xx_pe_yx_import_stats stats;
    if (!out || !xx_pe_yx_get_import_stats(data, size, &stats)) return false;
    out->standard_libraries = stats.standard_libraries;
    out->standard_functions = stats.standard_functions;
    out->delayed_libraries = stats.delayed_libraries;
    out->delayed_functions = stats.delayed_functions;
    return true;
}

typedef struct {
    const yx_pe_import_query *query;
    uint64_t count;
    uint64_t first_rva;
    bool found;
} yx_pe_import_match;

static void yx_pe_import_match_visit(void *opaque, const uint8_t *dll, size_t dll_length, const uint8_t *function, size_t function_length, bool by_ordinal,
                                     uint16_t ordinal, uint32_t rva)
{
    yx_pe_import_match *match = opaque;
    const yx_pe_import_query *query = match->query;
    if (query->dll_name && !yx_pe_ascii_equal(dll, dll_length, query->dll_name, query->dll_name_length)) return;
    if (query->by_ordinal) {
        if (!by_ordinal || ordinal != query->ordinal) return;
    } else if (query->function_name && !yx_pe_ascii_equal(function, function_length, query->function_name, query->function_name_length)) return;
    if (!match->found) match->first_rva = rva;
    match->found = true;
    ++match->count;
}

bool yx_pe_import_count(const uint8_t *data, size_t size, const yx_pe_import_query *query, uint64_t *count)
{
    yx_pe_import_match match = {0};
    if (!query || !count) return false;
    match.query = query;
    yx_pe_visit_imports(data, size, query->flags, yx_pe_import_match_visit, &match);
    *count = match.count;
    return true;
}

bool yx_pe_import_rva(const uint8_t *data, size_t size, bool delayed, const yx_pe_import_query *query, uint64_t *rva)
{
    yx_pe_import_match match = {0};
    if (!query || !rva) return false;
    match.query = query;
    yx_pe_visit_imports(data, size, delayed ? 2u : 1u, yx_pe_import_match_visit, &match);
    if (!match.found) return false;
    *rva = match.first_rva;
    return true;
}

bool yx_pe_imphash(const uint8_t *data, size_t size, char out[33])
{
    return xx_pe_yx_imphash(data, size, out);
}

bool yx_pe_parse_signatures(const uint8_t *data, size_t size, yx_pe_signature_result *result)
{
    return xx_pe_yx_parse_signatures(data, size, result);
}

void yx_pe_signature_result_destroy(yx_pe_signature_result *result)
{
    xx_pe_yx_signature_result_destroy(result);
}

bool yx_authenticode_parse_blob(const uint8_t *blob, size_t blob_size, yx_authenticode_hasher_fn hasher, void *hasher_opaque, yx_pe_signature_result *result)
{
    return xx_pe_yx_parse_blob(blob, blob_size, (xx_pe_yx_authenticode_hasher_fn)hasher, hasher_opaque, result);
}
