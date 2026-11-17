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


/* Internal collection schemas derived from the pinned YARA-X 1.21.0
 * protobuf field declarations. Native accessors remain the value authority. */

static yx_global_array yx_module_schema_crx_CrxSignature_array;
static yx_global_array yx_module_schema_crx_string_array;
static yx_global_array yx_module_schema_dex_ClassItem_array;
static yx_global_array yx_module_schema_dex_FieldItem_array;
static yx_global_array yx_module_schema_dex_MapItem_array;
static yx_global_array yx_module_schema_dex_MethodItem_array;
static yx_global_array yx_module_schema_dex_ProtoItem_array;
static yx_global_array yx_module_schema_dex_string_array;
static yx_global_array yx_module_schema_dotnet_AssemblyRef_array;
static yx_global_array yx_module_schema_dotnet_Class_array;
static yx_global_array yx_module_schema_dotnet_Method_array;
static yx_global_array yx_module_schema_dotnet_Param_array;
static yx_global_array yx_module_schema_dotnet_Resource_array;
static yx_global_array yx_module_schema_dotnet_Stream_array;
static yx_global_array yx_module_schema_dotnet_bytes_array;
static yx_global_array yx_module_schema_dotnet_string_array;
static yx_global_array yx_module_schema_dotnet_uint32_array;
static yx_global_array yx_module_schema_elf_Dyn_array;
static yx_global_array yx_module_schema_elf_Section_array;
static yx_global_array yx_module_schema_elf_Segment_array;
static yx_global_array yx_module_schema_elf_Sym_array;
static yx_global_array yx_module_schema_lnk_ShellItem_array;
static yx_global_array yx_module_schema_macho_BuildTool_array;
static yx_global_array yx_module_schema_macho_Certificate_array;
static yx_global_array yx_module_schema_macho_Dylib_array;
static yx_global_array yx_module_schema_macho_FatArch_array;
static yx_global_array yx_module_schema_macho_File_array;
static yx_global_array yx_module_schema_macho_Nlist_array;
static yx_global_array yx_module_schema_macho_Section_array;
static yx_global_array yx_module_schema_macho_Segment_array;
static yx_global_array yx_module_schema_macho_bytes_array;
static yx_global_array yx_module_schema_macho_string_array;
static yx_global_array yx_module_schema_pe_Certificate_array;
static yx_global_array yx_module_schema_pe_CounterSignature_array;
static yx_global_array yx_module_schema_pe_DirEntry_array;
static yx_global_array yx_module_schema_pe_Export_array;
static yx_global_array yx_module_schema_pe_Function_array;
static yx_global_array yx_module_schema_pe_Import_array;
static yx_global_array yx_module_schema_pe_KeyValue_array;
static yx_global_array yx_module_schema_pe_Resource_array;
static yx_global_array yx_module_schema_pe_RichTool_array;
static yx_global_array yx_module_schema_pe_Section_array;
static yx_global_array yx_module_schema_pe_Signature_array;
static yx_global_array yx_module_schema_zip_Entry_array;
static yx_global_field yx_module_schema_crx_CrxSignature_fields[] = {
    {.name = "key", .type = YX_GLOBAL_STR},
    {.name = "verified", .type = YX_GLOBAL_BOOL},
};
static yx_global_object yx_module_schema_crx_CrxSignature_object = { yx_module_schema_crx_CrxSignature_fields, 2 };
static yx_global_scalar_value yx_module_schema_crx_CrxSignature_item = { .object = &yx_module_schema_crx_CrxSignature_object };
static yx_global_field yx_module_schema_dex_ClassItem_fields[] = {
    {.name = "class", .type = YX_GLOBAL_STR},
    {.name = "access_flags", .type = YX_GLOBAL_INT},
    {.name = "superclass", .type = YX_GLOBAL_STR},
    {.name = "source_file", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_dex_ClassItem_object = { yx_module_schema_dex_ClassItem_fields, 4 };
static yx_global_scalar_value yx_module_schema_dex_ClassItem_item = { .object = &yx_module_schema_dex_ClassItem_object };
static yx_global_field yx_module_schema_dex_FieldItem_fields[] = {
    {.name = "class", .type = YX_GLOBAL_STR},
    {.name = "type", .type = YX_GLOBAL_STR},
    {.name = "name", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_dex_FieldItem_object = { yx_module_schema_dex_FieldItem_fields, 3 };
static yx_global_scalar_value yx_module_schema_dex_FieldItem_item = { .object = &yx_module_schema_dex_FieldItem_object };
static yx_global_field yx_module_schema_dex_MapItem_fields[] = {
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "unused", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_dex_MapItem_object = { yx_module_schema_dex_MapItem_fields, 4 };
static yx_global_scalar_value yx_module_schema_dex_MapItem_item = { .object = &yx_module_schema_dex_MapItem_object };
static yx_global_field yx_module_schema_dex_MethodItem_fields[] = {
    {.name = "class", .type = YX_GLOBAL_STR},
    {.name = "proto.shorty", .type = YX_GLOBAL_STR},
    {.name = "proto.return_type", .type = YX_GLOBAL_STR},
    {.name = "proto.parameters_count", .type = YX_GLOBAL_INT},
    {.name = "proto.parameters", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dex_string_array},
    {.name = "name", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_dex_MethodItem_object = { yx_module_schema_dex_MethodItem_fields, 6 };
static yx_global_scalar_value yx_module_schema_dex_MethodItem_item = { .object = &yx_module_schema_dex_MethodItem_object };
static yx_global_field yx_module_schema_dex_ProtoItem_fields[] = {
    {.name = "shorty", .type = YX_GLOBAL_STR},
    {.name = "return_type", .type = YX_GLOBAL_STR},
    {.name = "parameters_count", .type = YX_GLOBAL_INT},
    {.name = "parameters", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dex_string_array},
};
static yx_global_object yx_module_schema_dex_ProtoItem_object = { yx_module_schema_dex_ProtoItem_fields, 4 };
static yx_global_scalar_value yx_module_schema_dex_ProtoItem_item = { .object = &yx_module_schema_dex_ProtoItem_object };
static yx_global_field yx_module_schema_dotnet_AssemblyRef_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "public_key_or_token", .type = YX_GLOBAL_STR},
    {.name = "version.major", .type = YX_GLOBAL_INT},
    {.name = "version.minor", .type = YX_GLOBAL_INT},
    {.name = "version.build_number", .type = YX_GLOBAL_INT},
    {.name = "version.revision_number", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_dotnet_AssemblyRef_object = { yx_module_schema_dotnet_AssemblyRef_fields, 6 };
static yx_global_scalar_value yx_module_schema_dotnet_AssemblyRef_item = { .object = &yx_module_schema_dotnet_AssemblyRef_object };
static yx_global_field yx_module_schema_dotnet_Class_fields[] = {
    {.name = "fullname", .type = YX_GLOBAL_STR},
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "namespace", .type = YX_GLOBAL_STR},
    {.name = "visibility", .type = YX_GLOBAL_STR},
    {.name = "type", .type = YX_GLOBAL_STR},
    {.name = "abstract", .type = YX_GLOBAL_BOOL},
    {.name = "sealed", .type = YX_GLOBAL_BOOL},
    {.name = "number_of_base_types", .type = YX_GLOBAL_INT},
    {.name = "number_of_generic_parameters", .type = YX_GLOBAL_INT},
    {.name = "number_of_methods", .type = YX_GLOBAL_INT},
    {.name = "base_types", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dotnet_string_array},
    {.name = "generic_parameters", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dotnet_string_array},
    {.name = "methods", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dotnet_Method_array},
};
static yx_global_object yx_module_schema_dotnet_Class_object = { yx_module_schema_dotnet_Class_fields, 13 };
static yx_global_scalar_value yx_module_schema_dotnet_Class_item = { .object = &yx_module_schema_dotnet_Class_object };
static yx_global_field yx_module_schema_dotnet_Method_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "visibility", .type = YX_GLOBAL_STR},
    {.name = "abstract", .type = YX_GLOBAL_BOOL},
    {.name = "static", .type = YX_GLOBAL_BOOL},
    {.name = "virtual", .type = YX_GLOBAL_BOOL},
    {.name = "final", .type = YX_GLOBAL_BOOL},
    {.name = "return_type", .type = YX_GLOBAL_STR},
    {.name = "number_of_generic_parameters", .type = YX_GLOBAL_INT},
    {.name = "number_of_parameters", .type = YX_GLOBAL_INT},
    {.name = "generic_parameters", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dotnet_string_array},
    {.name = "parameters", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_dotnet_Param_array},
};
static yx_global_object yx_module_schema_dotnet_Method_object = { yx_module_schema_dotnet_Method_fields, 11 };
static yx_global_scalar_value yx_module_schema_dotnet_Method_item = { .object = &yx_module_schema_dotnet_Method_object };
static yx_global_field yx_module_schema_dotnet_Param_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "type", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_dotnet_Param_object = { yx_module_schema_dotnet_Param_fields, 2 };
static yx_global_scalar_value yx_module_schema_dotnet_Param_item = { .object = &yx_module_schema_dotnet_Param_object };
static yx_global_field yx_module_schema_dotnet_Resource_fields[] = {
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "length", .type = YX_GLOBAL_INT},
    {.name = "name", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_dotnet_Resource_object = { yx_module_schema_dotnet_Resource_fields, 3 };
static yx_global_scalar_value yx_module_schema_dotnet_Resource_item = { .object = &yx_module_schema_dotnet_Resource_object };
static yx_global_field yx_module_schema_dotnet_Stream_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_dotnet_Stream_object = { yx_module_schema_dotnet_Stream_fields, 3 };
static yx_global_scalar_value yx_module_schema_dotnet_Stream_item = { .object = &yx_module_schema_dotnet_Stream_object };
static yx_global_field yx_module_schema_elf_Dyn_fields[] = {
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "val", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_elf_Dyn_object = { yx_module_schema_elf_Dyn_fields, 2 };
static yx_global_scalar_value yx_module_schema_elf_Dyn_item = { .object = &yx_module_schema_elf_Dyn_object };
static yx_global_field yx_module_schema_elf_Section_fields[] = {
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "flags", .type = YX_GLOBAL_INT},
    {.name = "address", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "name", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_elf_Section_object = { yx_module_schema_elf_Section_fields, 6 };
static yx_global_scalar_value yx_module_schema_elf_Section_item = { .object = &yx_module_schema_elf_Section_object };
static yx_global_field yx_module_schema_elf_Segment_fields[] = {
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "flags", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "virtual_address", .type = YX_GLOBAL_INT},
    {.name = "physical_address", .type = YX_GLOBAL_INT},
    {.name = "file_size", .type = YX_GLOBAL_INT},
    {.name = "memory_size", .type = YX_GLOBAL_INT},
    {.name = "alignment", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_elf_Segment_object = { yx_module_schema_elf_Segment_fields, 8 };
static yx_global_scalar_value yx_module_schema_elf_Segment_item = { .object = &yx_module_schema_elf_Segment_object };
static yx_global_field yx_module_schema_elf_Sym_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "value", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "bind", .type = YX_GLOBAL_INT},
    {.name = "shndx", .type = YX_GLOBAL_INT},
    {.name = "visibility", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_elf_Sym_object = { yx_module_schema_elf_Sym_fields, 7 };
static yx_global_scalar_value yx_module_schema_elf_Sym_item = { .object = &yx_module_schema_elf_Sym_object };
static yx_global_field yx_module_schema_lnk_ShellItem_fields[] = {
    {.name = "item_type", .type = YX_GLOBAL_INT},
    {.name = "data", .type = YX_GLOBAL_STR},
    {.name = "cpl_file_path", .type = YX_GLOBAL_STR},
    {.name = "root_folder_id", .type = YX_GLOBAL_STR},
    {.name = "volume_name", .type = YX_GLOBAL_STR},
    {.name = "volume_id", .type = YX_GLOBAL_STR},
    {.name = "file_entry_name", .type = YX_GLOBAL_STR},
    {.name = "network_location", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_lnk_ShellItem_object = { yx_module_schema_lnk_ShellItem_fields, 8 };
static yx_global_scalar_value yx_module_schema_lnk_ShellItem_item = { .object = &yx_module_schema_lnk_ShellItem_object };
static yx_global_field yx_module_schema_macho_BuildTool_fields[] = {
    {.name = "tool", .type = YX_GLOBAL_INT},
    {.name = "version", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_macho_BuildTool_object = { yx_module_schema_macho_BuildTool_fields, 2 };
static yx_global_scalar_value yx_module_schema_macho_BuildTool_item = { .object = &yx_module_schema_macho_BuildTool_object };
static yx_global_field yx_module_schema_macho_Certificate_fields[] = {
    {.name = "issuer", .type = YX_GLOBAL_STR},
    {.name = "subject", .type = YX_GLOBAL_STR},
    {.name = "is_self_signed", .type = YX_GLOBAL_BOOL},
};
static yx_global_object yx_module_schema_macho_Certificate_object = { yx_module_schema_macho_Certificate_fields, 3 };
static yx_global_scalar_value yx_module_schema_macho_Certificate_item = { .object = &yx_module_schema_macho_Certificate_object };
static yx_global_field yx_module_schema_macho_Dylib_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "timestamp", .type = YX_GLOBAL_INT},
    {.name = "compatibility_version", .type = YX_GLOBAL_STR},
    {.name = "current_version", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_macho_Dylib_object = { yx_module_schema_macho_Dylib_fields, 4 };
static yx_global_scalar_value yx_module_schema_macho_Dylib_item = { .object = &yx_module_schema_macho_Dylib_object };
static yx_global_field yx_module_schema_macho_FatArch_fields[] = {
    {.name = "cputype", .type = YX_GLOBAL_INT},
    {.name = "cpusubtype", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
    {.name = "align", .type = YX_GLOBAL_INT},
    {.name = "reserved", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_macho_FatArch_object = { yx_module_schema_macho_FatArch_fields, 6 };
static yx_global_scalar_value yx_module_schema_macho_FatArch_item = { .object = &yx_module_schema_macho_FatArch_object };
static yx_global_field yx_module_schema_macho_File_fields[] = {
    {.name = "magic", .type = YX_GLOBAL_INT},
    {.name = "cputype", .type = YX_GLOBAL_INT},
    {.name = "cpusubtype", .type = YX_GLOBAL_INT},
    {.name = "filetype", .type = YX_GLOBAL_INT},
    {.name = "ncmds", .type = YX_GLOBAL_INT},
    {.name = "sizeofcmds", .type = YX_GLOBAL_INT},
    {.name = "flags", .type = YX_GLOBAL_INT},
    {.name = "reserved", .type = YX_GLOBAL_INT},
    {.name = "number_of_segments", .type = YX_GLOBAL_INT},
    {.name = "dynamic_linker", .type = YX_GLOBAL_STR},
    {.name = "entry_point", .type = YX_GLOBAL_INT},
    {.name = "stack_size", .type = YX_GLOBAL_INT},
    {.name = "source_version", .type = YX_GLOBAL_STR},
    {.name = "segments", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_Segment_array},
    {.name = "dylibs", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_Dylib_array},
    {.name = "rpaths", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_bytes_array},
    {.name = "entitlements", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_string_array},
    {.name = "symtab.symoff", .type = YX_GLOBAL_INT},
    {.name = "symtab.nsyms", .type = YX_GLOBAL_INT},
    {.name = "symtab.stroff", .type = YX_GLOBAL_INT},
    {.name = "symtab.strsize", .type = YX_GLOBAL_INT},
    {.name = "symtab.entries", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_bytes_array},
    {.name = "symtab.nlists", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_Nlist_array},
    {.name = "dysymtab.ilocalsym", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nlocalsym", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.iextdefsym", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nextdefsym", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.iundefsym", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nundefsym", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.tocoff", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.ntoc", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.modtaboff", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nmodtab", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.extrefsymoff", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nextrefsyms", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.indirectsymoff", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nindirectsyms", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.extreloff", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nextrel", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.locreloff", .type = YX_GLOBAL_INT},
    {.name = "dysymtab.nlocrel", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.rebase_off", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.rebase_size", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.bind_off", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.bind_size", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.weak_bind_off", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.weak_bind_size", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.lazy_bind_off", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.lazy_bind_size", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.export_off", .type = YX_GLOBAL_INT},
    {.name = "dyld_info.export_size", .type = YX_GLOBAL_INT},
    {.name = "code_signature_data.dataoff", .type = YX_GLOBAL_INT},
    {.name = "code_signature_data.datasize", .type = YX_GLOBAL_INT},
    {.name = "certificates", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_Certificate_array},
    {.name = "uuid", .type = YX_GLOBAL_STR},
    {.name = "build_version.platform", .type = YX_GLOBAL_INT},
    {.name = "build_version.minos", .type = YX_GLOBAL_STR},
    {.name = "build_version.sdk", .type = YX_GLOBAL_STR},
    {.name = "build_version.ntools", .type = YX_GLOBAL_INT},
    {.name = "build_version.tools", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_BuildTool_array},
    {.name = "min_version.device", .type = YX_GLOBAL_INT},
    {.name = "min_version.version", .type = YX_GLOBAL_STR},
    {.name = "min_version.sdk", .type = YX_GLOBAL_STR},
    {.name = "exports", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_string_array},
    {.name = "imports", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_string_array},
    {.name = "linker_options", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_bytes_array},
};
static yx_global_object yx_module_schema_macho_File_object = { yx_module_schema_macho_File_fields, 66 };
static yx_global_scalar_value yx_module_schema_macho_File_item = { .object = &yx_module_schema_macho_File_object };
static yx_global_field yx_module_schema_macho_Nlist_fields[] = {
    {.name = "n_strx", .type = YX_GLOBAL_INT},
    {.name = "n_type", .type = YX_GLOBAL_INT},
    {.name = "n_sect", .type = YX_GLOBAL_INT},
    {.name = "n_desc", .type = YX_GLOBAL_INT},
    {.name = "n_value", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_macho_Nlist_object = { yx_module_schema_macho_Nlist_fields, 5 };
static yx_global_scalar_value yx_module_schema_macho_Nlist_item = { .object = &yx_module_schema_macho_Nlist_object };
static yx_global_field yx_module_schema_macho_Section_fields[] = {
    {.name = "segname", .type = YX_GLOBAL_STR},
    {.name = "sectname", .type = YX_GLOBAL_STR},
    {.name = "addr", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "align", .type = YX_GLOBAL_INT},
    {.name = "reloff", .type = YX_GLOBAL_INT},
    {.name = "nreloc", .type = YX_GLOBAL_INT},
    {.name = "flags", .type = YX_GLOBAL_INT},
    {.name = "reserved1", .type = YX_GLOBAL_INT},
    {.name = "reserved2", .type = YX_GLOBAL_INT},
    {.name = "reserved3", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_macho_Section_object = { yx_module_schema_macho_Section_fields, 12 };
static yx_global_scalar_value yx_module_schema_macho_Section_item = { .object = &yx_module_schema_macho_Section_object };
static yx_global_field yx_module_schema_macho_Segment_fields[] = {
    {.name = "segname", .type = YX_GLOBAL_STR},
    {.name = "vmaddr", .type = YX_GLOBAL_INT},
    {.name = "vmsize", .type = YX_GLOBAL_INT},
    {.name = "fileoff", .type = YX_GLOBAL_INT},
    {.name = "filesize", .type = YX_GLOBAL_INT},
    {.name = "maxprot", .type = YX_GLOBAL_INT},
    {.name = "initprot", .type = YX_GLOBAL_INT},
    {.name = "nsects", .type = YX_GLOBAL_INT},
    {.name = "flags", .type = YX_GLOBAL_INT},
    {.name = "sections", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_macho_Section_array},
};
static yx_global_object yx_module_schema_macho_Segment_object = { yx_module_schema_macho_Segment_fields, 10 };
static yx_global_scalar_value yx_module_schema_macho_Segment_item = { .object = &yx_module_schema_macho_Segment_object };
static yx_global_field yx_module_schema_pe_Certificate_fields[] = {
    {.name = "issuer", .type = YX_GLOBAL_STR},
    {.name = "subject", .type = YX_GLOBAL_STR},
    {.name = "thumbprint", .type = YX_GLOBAL_STR},
    {.name = "version", .type = YX_GLOBAL_INT},
    {.name = "algorithm", .type = YX_GLOBAL_STR},
    {.name = "algorithm_oid", .type = YX_GLOBAL_STR},
    {.name = "serial", .type = YX_GLOBAL_STR},
    {.name = "not_before", .type = YX_GLOBAL_INT},
    {.name = "not_after", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_pe_Certificate_object = { yx_module_schema_pe_Certificate_fields, 9 };
static yx_global_scalar_value yx_module_schema_pe_Certificate_item = { .object = &yx_module_schema_pe_Certificate_object };
static yx_global_field yx_module_schema_pe_CounterSignature_fields[] = {
    {.name = "verified", .type = YX_GLOBAL_BOOL},
    {.name = "sign_time", .type = YX_GLOBAL_INT},
    {.name = "digest", .type = YX_GLOBAL_STR},
    {.name = "digest_alg", .type = YX_GLOBAL_STR},
    {.name = "chain", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_pe_Certificate_array},
};
static yx_global_object yx_module_schema_pe_CounterSignature_object = { yx_module_schema_pe_CounterSignature_fields, 5 };
static yx_global_scalar_value yx_module_schema_pe_CounterSignature_item = { .object = &yx_module_schema_pe_CounterSignature_object };
static yx_global_field yx_module_schema_pe_DirEntry_fields[] = {
    {.name = "virtual_address", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_pe_DirEntry_object = { yx_module_schema_pe_DirEntry_fields, 2 };
static yx_global_scalar_value yx_module_schema_pe_DirEntry_item = { .object = &yx_module_schema_pe_DirEntry_object };
static yx_global_field yx_module_schema_pe_Export_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "ordinal", .type = YX_GLOBAL_INT},
    {.name = "rva", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "forward_name", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_pe_Export_object = { yx_module_schema_pe_Export_fields, 5 };
static yx_global_scalar_value yx_module_schema_pe_Export_item = { .object = &yx_module_schema_pe_Export_object };
static yx_global_field yx_module_schema_pe_Function_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "ordinal", .type = YX_GLOBAL_INT},
    {.name = "rva", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_pe_Function_object = { yx_module_schema_pe_Function_fields, 3 };
static yx_global_scalar_value yx_module_schema_pe_Function_item = { .object = &yx_module_schema_pe_Function_object };
static yx_global_field yx_module_schema_pe_Import_fields[] = {
    {.name = "library_name", .type = YX_GLOBAL_STR},
    {.name = "number_of_functions", .type = YX_GLOBAL_INT},
    {.name = "functions", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_pe_Function_array},
};
static yx_global_object yx_module_schema_pe_Import_object = { yx_module_schema_pe_Import_fields, 3 };
static yx_global_scalar_value yx_module_schema_pe_Import_item = { .object = &yx_module_schema_pe_Import_object };
static yx_global_field yx_module_schema_pe_KeyValue_fields[] = {
    {.name = "key", .type = YX_GLOBAL_STR},
    {.name = "value", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_pe_KeyValue_object = { yx_module_schema_pe_KeyValue_fields, 2 };
static yx_global_scalar_value yx_module_schema_pe_KeyValue_item = { .object = &yx_module_schema_pe_KeyValue_object };
static yx_global_field yx_module_schema_pe_Resource_fields[] = {
    {.name = "length", .type = YX_GLOBAL_INT},
    {.name = "rva", .type = YX_GLOBAL_INT},
    {.name = "offset", .type = YX_GLOBAL_INT},
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "id", .type = YX_GLOBAL_INT},
    {.name = "language", .type = YX_GLOBAL_INT},
    {.name = "type_string", .type = YX_GLOBAL_STR},
    {.name = "name_string", .type = YX_GLOBAL_STR},
    {.name = "language_string", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_pe_Resource_object = { yx_module_schema_pe_Resource_fields, 9 };
static yx_global_scalar_value yx_module_schema_pe_Resource_item = { .object = &yx_module_schema_pe_Resource_object };
static yx_global_field yx_module_schema_pe_RichTool_fields[] = {
    {.name = "toolid", .type = YX_GLOBAL_INT},
    {.name = "version", .type = YX_GLOBAL_INT},
    {.name = "times", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_pe_RichTool_object = { yx_module_schema_pe_RichTool_fields, 3 };
static yx_global_scalar_value yx_module_schema_pe_RichTool_item = { .object = &yx_module_schema_pe_RichTool_object };
static yx_global_field yx_module_schema_pe_Section_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "full_name", .type = YX_GLOBAL_STR},
    {.name = "characteristics", .type = YX_GLOBAL_INT},
    {.name = "raw_data_size", .type = YX_GLOBAL_INT},
    {.name = "raw_data_offset", .type = YX_GLOBAL_INT},
    {.name = "virtual_address", .type = YX_GLOBAL_INT},
    {.name = "virtual_size", .type = YX_GLOBAL_INT},
    {.name = "pointer_to_relocations", .type = YX_GLOBAL_INT},
    {.name = "pointer_to_line_numbers", .type = YX_GLOBAL_INT},
    {.name = "number_of_relocations", .type = YX_GLOBAL_INT},
    {.name = "number_of_line_numbers", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_pe_Section_object = { yx_module_schema_pe_Section_fields, 11 };
static yx_global_scalar_value yx_module_schema_pe_Section_item = { .object = &yx_module_schema_pe_Section_object };
static yx_global_field yx_module_schema_pe_Signature_fields[] = {
    {.name = "subject", .type = YX_GLOBAL_STR},
    {.name = "issuer", .type = YX_GLOBAL_STR},
    {.name = "thumbprint", .type = YX_GLOBAL_STR},
    {.name = "version", .type = YX_GLOBAL_INT},
    {.name = "algorithm", .type = YX_GLOBAL_STR},
    {.name = "algorithm_oid", .type = YX_GLOBAL_STR},
    {.name = "serial", .type = YX_GLOBAL_STR},
    {.name = "not_before", .type = YX_GLOBAL_INT},
    {.name = "not_after", .type = YX_GLOBAL_INT},
    {.name = "verified", .type = YX_GLOBAL_BOOL},
    {.name = "digest_alg", .type = YX_GLOBAL_STR},
    {.name = "digest", .type = YX_GLOBAL_STR},
    {.name = "file_digest", .type = YX_GLOBAL_STR},
    {.name = "number_of_certificates", .type = YX_GLOBAL_INT},
    {.name = "number_of_countersignatures", .type = YX_GLOBAL_INT},
    {.name = "signer_info.program_name", .type = YX_GLOBAL_STR},
    {.name = "signer_info.more_info", .type = YX_GLOBAL_STR},
    {.name = "signer_info.digest", .type = YX_GLOBAL_STR},
    {.name = "signer_info.digest_alg", .type = YX_GLOBAL_STR},
    {.name = "signer_info.chain", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_pe_Certificate_array},
    {.name = "certificates", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_pe_Certificate_array},
    {.name = "countersignatures", .type = YX_GLOBAL_ARRAY, .value.array = &yx_module_schema_pe_CounterSignature_array},
};
static yx_global_object yx_module_schema_pe_Signature_object = { yx_module_schema_pe_Signature_fields, 22 };
static yx_global_scalar_value yx_module_schema_pe_Signature_item = { .object = &yx_module_schema_pe_Signature_object };
static yx_global_field yx_module_schema_zip_Entry_fields[] = {
    {.name = "file_path", .type = YX_GLOBAL_STR},
    {.name = "compression", .type = YX_GLOBAL_INT},
    {.name = "uncompressed_size", .type = YX_GLOBAL_INT},
    {.name = "compressed_size", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_zip_Entry_object = { yx_module_schema_zip_Entry_fields, 4 };
static yx_global_scalar_value yx_module_schema_zip_Entry_item = { .object = &yx_module_schema_zip_Entry_object };
static yx_global_array yx_module_schema_crx_CrxSignature_array = { YX_GLOBAL_STRUCT, &yx_module_schema_crx_CrxSignature_item, 1 };
static yx_global_array yx_module_schema_crx_string_array = { YX_GLOBAL_STR, NULL, 0 };
static yx_global_array yx_module_schema_dex_ClassItem_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dex_ClassItem_item, 1 };
static yx_global_array yx_module_schema_dex_FieldItem_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dex_FieldItem_item, 1 };
static yx_global_array yx_module_schema_dex_MapItem_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dex_MapItem_item, 1 };
static yx_global_array yx_module_schema_dex_MethodItem_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dex_MethodItem_item, 1 };
static yx_global_array yx_module_schema_dex_ProtoItem_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dex_ProtoItem_item, 1 };
static yx_global_array yx_module_schema_dex_string_array = { YX_GLOBAL_STR, NULL, 0 };
static yx_global_array yx_module_schema_dotnet_AssemblyRef_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dotnet_AssemblyRef_item, 1 };
static yx_global_array yx_module_schema_dotnet_Class_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dotnet_Class_item, 1 };
static yx_global_array yx_module_schema_dotnet_Method_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dotnet_Method_item, 1 };
static yx_global_array yx_module_schema_dotnet_Param_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dotnet_Param_item, 1 };
static yx_global_array yx_module_schema_dotnet_Resource_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dotnet_Resource_item, 1 };
static yx_global_array yx_module_schema_dotnet_Stream_array = { YX_GLOBAL_STRUCT, &yx_module_schema_dotnet_Stream_item, 1 };
static yx_global_array yx_module_schema_dotnet_bytes_array = { YX_GLOBAL_STR, NULL, 0 };
static yx_global_array yx_module_schema_dotnet_string_array = { YX_GLOBAL_STR, NULL, 0 };
static yx_global_array yx_module_schema_dotnet_uint32_array = { YX_GLOBAL_INT, NULL, 0 };
static yx_global_array yx_module_schema_elf_Dyn_array = { YX_GLOBAL_STRUCT, &yx_module_schema_elf_Dyn_item, 1 };
static yx_global_array yx_module_schema_elf_Section_array = { YX_GLOBAL_STRUCT, &yx_module_schema_elf_Section_item, 1 };
static yx_global_array yx_module_schema_elf_Segment_array = { YX_GLOBAL_STRUCT, &yx_module_schema_elf_Segment_item, 1 };
static yx_global_array yx_module_schema_elf_Sym_array = { YX_GLOBAL_STRUCT, &yx_module_schema_elf_Sym_item, 1 };
static yx_global_array yx_module_schema_lnk_ShellItem_array = { YX_GLOBAL_STRUCT, &yx_module_schema_lnk_ShellItem_item, 1 };
static yx_global_array yx_module_schema_macho_BuildTool_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_BuildTool_item, 1 };
static yx_global_array yx_module_schema_macho_Certificate_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_Certificate_item, 1 };
static yx_global_array yx_module_schema_macho_Dylib_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_Dylib_item, 1 };
static yx_global_array yx_module_schema_macho_FatArch_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_FatArch_item, 1 };
static yx_global_array yx_module_schema_macho_File_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_File_item, 1 };
static yx_global_array yx_module_schema_macho_Nlist_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_Nlist_item, 1 };
static yx_global_array yx_module_schema_macho_Section_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_Section_item, 1 };
static yx_global_array yx_module_schema_macho_Segment_array = { YX_GLOBAL_STRUCT, &yx_module_schema_macho_Segment_item, 1 };
static yx_global_array yx_module_schema_macho_bytes_array = { YX_GLOBAL_STR, NULL, 0 };
static yx_global_array yx_module_schema_macho_string_array = { YX_GLOBAL_STR, NULL, 0 };
static yx_global_array yx_module_schema_pe_Certificate_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Certificate_item, 1 };
static yx_global_array yx_module_schema_pe_CounterSignature_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_CounterSignature_item, 1 };
static yx_global_array yx_module_schema_pe_DirEntry_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_DirEntry_item, 1 };
static yx_global_array yx_module_schema_pe_Export_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Export_item, 1 };
static yx_global_array yx_module_schema_pe_Function_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Function_item, 1 };
static yx_global_array yx_module_schema_pe_Import_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Import_item, 1 };
static yx_global_array yx_module_schema_pe_KeyValue_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_KeyValue_item, 1 };
static yx_global_array yx_module_schema_pe_Resource_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Resource_item, 1 };
static yx_global_array yx_module_schema_pe_RichTool_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_RichTool_item, 1 };
static yx_global_array yx_module_schema_pe_Section_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Section_item, 1 };
static yx_global_array yx_module_schema_pe_Signature_array = { YX_GLOBAL_STRUCT, &yx_module_schema_pe_Signature_item, 1 };
static yx_global_array yx_module_schema_zip_Entry_array = { YX_GLOBAL_STRUCT, &yx_module_schema_zip_Entry_item, 1 };
#ifdef XXYARA_ENABLE_OLECF
static yx_global_field yx_module_schema_olecf_Stream_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "size", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_module_schema_olecf_Stream_object = { yx_module_schema_olecf_Stream_fields, 3 };
static yx_global_scalar_value yx_module_schema_olecf_Stream_item = { .object = &yx_module_schema_olecf_Stream_object };
static yx_global_array yx_module_schema_olecf_Stream_array = { YX_GLOBAL_STRUCT, &yx_module_schema_olecf_Stream_item, 1 };
#endif
#ifdef XXYARA_ENABLE_VBA
static yx_global_field yx_module_schema_vba_Module_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "code", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_module_schema_vba_Module_object = { yx_module_schema_vba_Module_fields, 3 };
static yx_global_scalar_value yx_module_schema_vba_Module_item = { .object = &yx_module_schema_vba_Module_object };
static yx_global_array yx_module_schema_vba_Module_array = { YX_GLOBAL_STRUCT, &yx_module_schema_vba_Module_item, 1 };
static yx_global_array yx_module_schema_vba_string_array = { YX_GLOBAL_STR, NULL, 0 };
#endif
static const yx_module_array_desc yx_module_arrays[] = {
#ifdef XXYARA_ENABLE_OLECF
    {"olecf.streams", &yx_module_schema_olecf_Stream_array, 0},
#endif
#ifdef XXYARA_ENABLE_VBA
    {"vba.modules", &yx_module_schema_vba_Module_array, 0},
    {"vba.project_info.references", &yx_module_schema_vba_string_array, 0},
#endif
#ifdef XXYARA_ENABLE_MSI
    /* msi.signatures is a repeated pe.Signature (msi.proto). */
    {"msi.signatures", &yx_module_schema_pe_Signature_array, 0},
    {"msi.signatures.certificates", &yx_module_schema_pe_Certificate_array, 1},
    {"msi.signatures.countersignatures", &yx_module_schema_pe_CounterSignature_array, 1},
    {"msi.signatures.countersignatures.chain", &yx_module_schema_pe_Certificate_array, 2},
    {"msi.signatures.signer_info.chain", &yx_module_schema_pe_Certificate_array, 1},
#endif
    {"crx.host_permissions", &yx_module_schema_crx_string_array, 0},
    {"crx.optional_host_permissions", &yx_module_schema_crx_string_array, 0},
    {"crx.optional_permissions", &yx_module_schema_crx_string_array, 0},
    {"crx.permissions", &yx_module_schema_crx_string_array, 0},
    {"crx.signatures", &yx_module_schema_crx_CrxSignature_array, 0},
    {"dex.class_defs", &yx_module_schema_dex_ClassItem_array, 0},
    {"dex.fields", &yx_module_schema_dex_FieldItem_array, 0},
    {"dex.map_list.items", &yx_module_schema_dex_MapItem_array, 0},
    {"dex.methods", &yx_module_schema_dex_MethodItem_array, 0},
    {"dex.methods.proto.parameters", &yx_module_schema_dex_string_array, 1},
    {"dex.protos", &yx_module_schema_dex_ProtoItem_array, 0},
    {"dex.protos.parameters", &yx_module_schema_dex_string_array, 1},
    {"dex.types", &yx_module_schema_dex_string_array, 0},
    {"dotnet.assembly_refs", &yx_module_schema_dotnet_AssemblyRef_array, 0},
    {"dotnet.classes", &yx_module_schema_dotnet_Class_array, 0},
    {"dotnet.classes.base_types", &yx_module_schema_dotnet_string_array, 1},
    {"dotnet.classes.generic_parameters", &yx_module_schema_dotnet_string_array, 1},
    {"dotnet.classes.methods", &yx_module_schema_dotnet_Method_array, 1},
    {"dotnet.classes.methods.generic_parameters", &yx_module_schema_dotnet_string_array, 2},
    {"dotnet.classes.methods.parameters", &yx_module_schema_dotnet_Param_array, 2},
    {"dotnet.constants", &yx_module_schema_dotnet_bytes_array, 0},
    {"dotnet.field_offsets", &yx_module_schema_dotnet_uint32_array, 0},
    {"dotnet.guids", &yx_module_schema_dotnet_string_array, 0},
    {"dotnet.modulerefs", &yx_module_schema_dotnet_string_array, 0},
    {"dotnet.resources", &yx_module_schema_dotnet_Resource_array, 0},
    {"dotnet.streams", &yx_module_schema_dotnet_Stream_array, 0},
    {"dotnet.user_strings", &yx_module_schema_dotnet_bytes_array, 0},
    {"elf.dynamic", &yx_module_schema_elf_Dyn_array, 0},
    {"elf.dynsym", &yx_module_schema_elf_Sym_array, 0},
    {"elf.sections", &yx_module_schema_elf_Section_array, 0},
    {"elf.segments", &yx_module_schema_elf_Segment_array, 0},
    {"elf.symtab", &yx_module_schema_elf_Sym_array, 0},
    {"lnk.target_id_list", &yx_module_schema_lnk_ShellItem_array, 0},
    {"macho.build_version.tools", &yx_module_schema_macho_BuildTool_array, 0},
    {"macho.certificates", &yx_module_schema_macho_Certificate_array, 0},
    {"macho.dylibs", &yx_module_schema_macho_Dylib_array, 0},
    {"macho.entitlements", &yx_module_schema_macho_string_array, 0},
    {"macho.exports", &yx_module_schema_macho_string_array, 0},
    {"macho.fat_arch", &yx_module_schema_macho_FatArch_array, 0},
    {"macho.file", &yx_module_schema_macho_File_array, 0},
    {"macho.file.build_version.tools", &yx_module_schema_macho_BuildTool_array, 1},
    {"macho.file.certificates", &yx_module_schema_macho_Certificate_array, 1},
    {"macho.file.dylibs", &yx_module_schema_macho_Dylib_array, 1},
    {"macho.file.entitlements", &yx_module_schema_macho_string_array, 1},
    {"macho.file.exports", &yx_module_schema_macho_string_array, 1},
    {"macho.file.imports", &yx_module_schema_macho_string_array, 1},
    {"macho.file.linker_options", &yx_module_schema_macho_bytes_array, 1},
    {"macho.file.rpaths", &yx_module_schema_macho_bytes_array, 1},
    {"macho.file.segments", &yx_module_schema_macho_Segment_array, 1},
    {"macho.file.segments.sections", &yx_module_schema_macho_Section_array, 2},
    {"macho.file.symtab.entries", &yx_module_schema_macho_bytes_array, 1},
    {"macho.file.symtab.nlists", &yx_module_schema_macho_Nlist_array, 1},
    {"macho.imports", &yx_module_schema_macho_string_array, 0},
    {"macho.linker_options", &yx_module_schema_macho_bytes_array, 0},
    {"macho.rpaths", &yx_module_schema_macho_bytes_array, 0},
    {"macho.segments", &yx_module_schema_macho_Segment_array, 0},
    {"macho.segments.sections", &yx_module_schema_macho_Section_array, 1},
    {"macho.symtab.entries", &yx_module_schema_macho_bytes_array, 0},
    {"macho.symtab.nlists", &yx_module_schema_macho_Nlist_array, 0},
    {"pe.data_directories", &yx_module_schema_pe_DirEntry_array, 0},
    {"pe.delayed_import_details", &yx_module_schema_pe_Import_array, 0},
    {"pe.delayed_import_details.functions", &yx_module_schema_pe_Function_array, 1},
    {"pe.export_details", &yx_module_schema_pe_Export_array, 0},
    {"pe.import_details", &yx_module_schema_pe_Import_array, 0},
    {"pe.import_details.functions", &yx_module_schema_pe_Function_array, 1},
    {"pe.resources", &yx_module_schema_pe_Resource_array, 0},
    {"pe.rich_signature.tools", &yx_module_schema_pe_RichTool_array, 0},
    {"pe.sections", &yx_module_schema_pe_Section_array, 0},
    {"pe.signatures", &yx_module_schema_pe_Signature_array, 0},
    {"pe.signatures.certificates", &yx_module_schema_pe_Certificate_array, 1},
    {"pe.signatures.countersignatures", &yx_module_schema_pe_CounterSignature_array, 1},
    {"pe.signatures.countersignatures.chain", &yx_module_schema_pe_Certificate_array, 2},
    {"pe.signatures.signer_info.chain", &yx_module_schema_pe_Certificate_array, 1},
    {"pe.version_info_list", &yx_module_schema_pe_KeyValue_array, 0},
    {"zip.entries", &yx_module_schema_zip_Entry_array, 0},
};
