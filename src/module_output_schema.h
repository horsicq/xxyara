/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


/* Generated from private_docs/MODULE_OUTPUT_SCHEMA.json; integer field types
 * aligned with YARA-X v1.23.0 module protobufs. */
static const yx_mo_wire_field yx_mo_fields_crx_Crx[] = {
    {"is_crx", 1, YX_MOW_BOOL, 0, 8},
    {"crx_version", 2, YX_MOW_UINT32, 0, 8},
    {"header_size", 3, YX_MOW_UINT32, 0, 8},
    {"id", 4, YX_MOW_STRING, 0, 8},
    {"version", 16, YX_MOW_STRING, 0, 8},
    {"name", 5, YX_MOW_STRING, 0, 8},
    {"description", 6, YX_MOW_STRING, 0, 8},
    {"raw_name", 7, YX_MOW_STRING, 0, 8},
    {"raw_description", 8, YX_MOW_STRING, 0, 8},
    {"minimum_chrome_version", 9, YX_MOW_STRING, 0, 8},
    {"homepage_url", 10, YX_MOW_STRING, 0, 8},
    {"permissions", 11, YX_MOW_STRING, 0, 1},
    {"host_permissions", 12, YX_MOW_STRING, 0, 1},
    {"optional_permissions", 13, YX_MOW_STRING, 0, 1},
    {"optional_host_permissions", 14, YX_MOW_STRING, 0, 1},
    {"signatures", 15, YX_MOW_MESSAGE, 1, 1},
};
static const yx_mo_wire_field yx_mo_fields_crx_CrxSignature[] = {
    {"key", 1, YX_MOW_STRING, 0, 24},
    {"verified", 2, YX_MOW_BOOL, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_dex_ClassItem[] = {
    {"class", 1, YX_MOW_STRING, 0, 8},
    {"access_flags", 2, YX_MOW_UINT32, 0, 8},
    {"superclass", 3, YX_MOW_STRING, 0, 8},
    {"source_file", 4, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dex_Dex[] = {
    {"is_dex", 1, YX_MOW_BOOL, 0, 8},
    {"header", 2, YX_MOW_MESSAGE, 4, 8},
    {"strings", 3, YX_MOW_STRING, 0, 1},
    {"types", 4, YX_MOW_STRING, 0, 1},
    {"protos", 5, YX_MOW_MESSAGE, 9, 1},
    {"fields", 6, YX_MOW_MESSAGE, 5, 1},
    {"methods", 7, YX_MOW_MESSAGE, 8, 1},
    {"class_defs", 8, YX_MOW_MESSAGE, 2, 1},
    {"map_list", 9, YX_MOW_MESSAGE, 7, 8},
};
static const yx_mo_wire_field yx_mo_fields_dex_DexHeader[] = {
    {"magic", 1, YX_MOW_UINT32, 0, 8},
    {"version", 2, YX_MOW_UINT32, 0, 8},
    {"checksum", 3, YX_MOW_UINT32, 0, 8},
    {"signature", 4, YX_MOW_STRING, 0, 8},
    {"file_size", 5, YX_MOW_UINT32, 0, 8},
    {"header_size", 6, YX_MOW_UINT32, 0, 8},
    {"endian_tag", 7, YX_MOW_UINT32, 0, 8},
    {"link_size", 8, YX_MOW_UINT32, 0, 8},
    {"link_off", 9, YX_MOW_UINT32, 0, 8},
    {"data_size", 23, YX_MOW_UINT32, 0, 8},
    {"data_off", 24, YX_MOW_UINT32, 0, 8},
    {"container_size", 25, YX_MOW_UINT32, 0, 8},
    {"header_offset", 26, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dex_FieldItem[] = {
    {"class", 1, YX_MOW_STRING, 0, 8},
    {"type", 2, YX_MOW_STRING, 0, 8},
    {"name", 3, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dex_MapItem[] = {
    {"type", 1, YX_MOW_INT32, 0, 8},
    {"unused", 2, YX_MOW_UINT32, 0, 8},
    {"size", 3, YX_MOW_UINT32, 0, 8},
    {"offset", 4, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dex_MapList[] = {
    {"size", 1, YX_MOW_UINT32, 0, 8},
    {"items", 2, YX_MOW_MESSAGE, 6, 1},
};
static const yx_mo_wire_field yx_mo_fields_dex_MethodItem[] = {
    {"class", 1, YX_MOW_STRING, 0, 8},
    {"proto", 2, YX_MOW_MESSAGE, 9, 8},
    {"name", 3, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dex_ProtoItem[] = {
    {"shorty", 1, YX_MOW_STRING, 0, 8},
    {"return_type", 2, YX_MOW_STRING, 0, 8},
    {"parameters_count", 3, YX_MOW_UINT32, 0, 8},
    {"parameters", 4, YX_MOW_STRING, 0, 1},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Assembly[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"culture", 2, YX_MOW_STRING, 0, 8},
    {"version", 3, YX_MOW_MESSAGE, 18, 24},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_AssemblyRef[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"public_key_or_token", 2, YX_MOW_STRING, 0, 12},
    {"version", 3, YX_MOW_MESSAGE, 18, 24},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Class[] = {
    {"fullname", 1, YX_MOW_STRING, 0, 8},
    {"name", 2, YX_MOW_STRING, 0, 8},
    {"namespace", 3, YX_MOW_STRING, 0, 8},
    {"visibility", 4, YX_MOW_STRING, 0, 8},
    {"type", 5, YX_MOW_STRING, 0, 8},
    {"abstract", 6, YX_MOW_BOOL, 0, 24},
    {"sealed", 7, YX_MOW_BOOL, 0, 24},
    {"number_of_base_types", 8, YX_MOW_INT64, 0, 24},
    {"number_of_generic_parameters", 9, YX_MOW_INT64, 0, 24},
    {"number_of_methods", 10, YX_MOW_INT64, 0, 24},
    {"base_types", 11, YX_MOW_STRING, 0, 1},
    {"generic_parameters", 12, YX_MOW_STRING, 0, 1},
    {"methods", 13, YX_MOW_MESSAGE, 14, 1},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Dotnet[] = {
    {"is_dotnet", 1, YX_MOW_BOOL, 0, 8},
    {"module_name", 2, YX_MOW_STRING, 0, 8},
    {"version", 3, YX_MOW_STRING, 0, 8},
    {"number_of_streams", 4, YX_MOW_INT64, 0, 8},
    {"number_of_guids", 5, YX_MOW_INT64, 0, 8},
    {"number_of_resources", 6, YX_MOW_INT64, 0, 8},
    {"number_of_generic_parameters", 7, YX_MOW_INT64, 0, 8},
    {"number_of_classes", 10, YX_MOW_INT64, 0, 8},
    {"number_of_assembly_refs", 11, YX_MOW_INT64, 0, 8},
    {"number_of_modulerefs", 12, YX_MOW_INT64, 0, 8},
    {"number_of_user_strings", 13, YX_MOW_INT64, 0, 8},
    {"number_of_constants", 14, YX_MOW_INT64, 0, 8},
    {"number_of_field_offsets", 15, YX_MOW_INT64, 0, 8},
    {"typelib", 16, YX_MOW_STRING, 0, 8},
    {"streams", 17, YX_MOW_MESSAGE, 17, 1},
    {"guids", 18, YX_MOW_STRING, 0, 1},
    {"constants", 19, YX_MOW_STRING, 0, 5},
    {"assembly", 20, YX_MOW_MESSAGE, 10, 8},
    {"assembly_refs", 21, YX_MOW_MESSAGE, 11, 1},
    {"resources", 22, YX_MOW_MESSAGE, 16, 1},
    {"classes", 23, YX_MOW_MESSAGE, 12, 1},
    {"field_offsets", 24, YX_MOW_UINT32, 0, 1},
    {"user_strings", 25, YX_MOW_STRING, 0, 5},
    {"modulerefs", 26, YX_MOW_STRING, 0, 1},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Method[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"visibility", 2, YX_MOW_STRING, 0, 8},
    {"abstract", 3, YX_MOW_BOOL, 0, 24},
    {"static", 4, YX_MOW_BOOL, 0, 24},
    {"virtual", 5, YX_MOW_BOOL, 0, 24},
    {"final", 6, YX_MOW_BOOL, 0, 24},
    {"return_type", 7, YX_MOW_STRING, 0, 8},
    {"number_of_generic_parameters", 8, YX_MOW_INT64, 0, 24},
    {"number_of_parameters", 9, YX_MOW_INT64, 0, 24},
    {"generic_parameters", 10, YX_MOW_STRING, 0, 1},
    {"parameters", 11, YX_MOW_MESSAGE, 15, 1},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Param[] = {
    {"name", 1, YX_MOW_STRING, 0, 24},
    {"type", 2, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Resource[] = {
    {"offset", 1, YX_MOW_UINT32, 0, 8},
    {"length", 2, YX_MOW_UINT32, 0, 8},
    {"name", 3, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Stream[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"offset", 2, YX_MOW_UINT32, 0, 24},
    {"size", 3, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_dotnet_Version[] = {
    {"major", 1, YX_MOW_UINT32, 0, 24},
    {"minor", 2, YX_MOW_UINT32, 0, 24},
    {"build_number", 3, YX_MOW_UINT32, 0, 24},
    {"revision_number", 4, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_elf_Dyn[] = {
    {"type", 1, YX_MOW_INT32, 0, 8},
    {"val", 2, YX_MOW_INT64, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_elf_ELF[] = {
    {"type", 1, YX_MOW_INT32, 0, 8},
    {"machine", 2, YX_MOW_INT32, 0, 8},
    {"osabi", 18, YX_MOW_INT32, 0, 8},
    {"entry_point", 3, YX_MOW_INT64, 0, 8},
    {"sh_offset", 4, YX_MOW_INT64, 0, 8},
    {"sh_entry_size", 5, YX_MOW_UINT32, 0, 8},
    {"ph_offset", 6, YX_MOW_INT64, 0, 8},
    {"ph_entry_size", 7, YX_MOW_UINT32, 0, 8},
    {"number_of_sections", 8, YX_MOW_INT64, 0, 8},
    {"number_of_segments", 9, YX_MOW_INT64, 0, 8},
    {"symtab_entries", 10, YX_MOW_INT64, 0, 8},
    {"dynsym_entries", 11, YX_MOW_INT64, 0, 8},
    {"dynamic_section_entries", 12, YX_MOW_INT64, 0, 8},
    {"sections", 13, YX_MOW_MESSAGE, 21, 1},
    {"segments", 14, YX_MOW_MESSAGE, 22, 1},
    {"symtab", 15, YX_MOW_MESSAGE, 23, 1},
    {"dynsym", 16, YX_MOW_MESSAGE, 23, 1},
    {"dynamic", 17, YX_MOW_MESSAGE, 19, 1},
};
static const yx_mo_wire_field yx_mo_fields_elf_Section[] = {
    {"type", 1, YX_MOW_INT32, 0, 24},
    {"flags", 2, YX_MOW_INT64, 0, 24},
    {"address", 3, YX_MOW_INT64, 0, 24},
    {"size", 4, YX_MOW_INT64, 0, 24},
    {"offset", 5, YX_MOW_INT64, 0, 24},
    {"name", 6, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_elf_Segment[] = {
    {"type", 1, YX_MOW_INT32, 0, 24},
    {"flags", 2, YX_MOW_UINT32, 0, 24},
    {"offset", 3, YX_MOW_INT64, 0, 24},
    {"virtual_address", 4, YX_MOW_INT64, 0, 24},
    {"physical_address", 5, YX_MOW_INT64, 0, 24},
    {"file_size", 6, YX_MOW_INT64, 0, 24},
    {"memory_size", 7, YX_MOW_INT64, 0, 24},
    {"alignment", 8, YX_MOW_INT64, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_elf_Sym[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"value", 2, YX_MOW_INT64, 0, 24},
    {"size", 3, YX_MOW_INT64, 0, 24},
    {"type", 4, YX_MOW_INT32, 0, 24},
    {"bind", 5, YX_MOW_INT32, 0, 24},
    {"shndx", 6, YX_MOW_UINT32, 0, 24},
    {"visibility", 7, YX_MOW_INT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_lnk_Lnk[] = {
    {"is_lnk", 1, YX_MOW_BOOL, 0, 24},
    {"name", 2, YX_MOW_STRING, 0, 8},
    {"creation_time", 3, YX_MOW_INT64, 0, 8},
    {"access_time", 4, YX_MOW_INT64, 0, 8},
    {"write_time", 5, YX_MOW_INT64, 0, 8},
    {"file_size", 6, YX_MOW_UINT32, 0, 8},
    {"file_attributes", 7, YX_MOW_UINT32, 0, 8},
    {"icon_location", 8, YX_MOW_STRING, 0, 8},
    {"icon_index", 9, YX_MOW_UINT32, 0, 8},
    {"show_command", 10, YX_MOW_INT32, 0, 8},
    {"drive_type", 11, YX_MOW_INT32, 0, 8},
    {"drive_serial_number", 12, YX_MOW_UINT32, 0, 8},
    {"volume_label", 13, YX_MOW_STRING, 0, 8},
    {"local_base_path", 14, YX_MOW_STRING, 0, 8},
    {"common_path_suffix", 15, YX_MOW_STRING, 0, 8},
    {"relative_path", 16, YX_MOW_STRING, 0, 8},
    {"working_dir", 17, YX_MOW_STRING, 0, 8},
    {"cmd_line_args", 18, YX_MOW_STRING, 0, 8},
    {"overlay_size", 19, YX_MOW_INT64, 0, 8},
    {"overlay_offset", 20, YX_MOW_INT64, 0, 8},
    {"tracker_data", 21, YX_MOW_MESSAGE, 26, 8},
    {"target_id_list", 22, YX_MOW_MESSAGE, 25, 1},
};
static const yx_mo_wire_field yx_mo_fields_lnk_ShellItem[] = {
    {"item_type", 1, YX_MOW_INT32, 0, 8},
    {"data", 3, YX_MOW_STRING, 0, 12},
    {"cpl_file_path", 4, YX_MOW_STRING, 0, 8},
    {"root_folder_id", 5, YX_MOW_STRING, 0, 8},
    {"volume_name", 6, YX_MOW_STRING, 0, 8},
    {"volume_id", 7, YX_MOW_STRING, 0, 8},
    {"file_entry_name", 8, YX_MOW_STRING, 0, 8},
    {"network_location", 9, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_lnk_TrackerData[] = {
    {"version", 1, YX_MOW_UINT32, 0, 8},
    {"machine_id", 2, YX_MOW_STRING, 0, 8},
    {"droid_volume_id", 3, YX_MOW_STRING, 0, 8},
    {"droid_file_id", 4, YX_MOW_STRING, 0, 8},
    {"droid_birth_volume_id", 5, YX_MOW_STRING, 0, 8},
    {"droid_birth_file_id", 6, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_BuildTool[] = {
    {"tool", 1, YX_MOW_UINT32, 0, 8},
    {"version", 2, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_BuildVersion[] = {
    {"platform", 1, YX_MOW_UINT32, 0, 8},
    {"minos", 2, YX_MOW_STRING, 0, 8},
    {"sdk", 3, YX_MOW_STRING, 0, 8},
    {"ntools", 4, YX_MOW_UINT32, 0, 8},
    {"tools", 5, YX_MOW_MESSAGE, 27, 1},
};
static const yx_mo_wire_field yx_mo_fields_macho_Certificate[] = {
    {"issuer", 1, YX_MOW_STRING, 0, 24},
    {"subject", 2, YX_MOW_STRING, 0, 24},
    {"is_self_signed", 3, YX_MOW_BOOL, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_macho_DyldInfo[] = {
    {"rebase_off", 1, YX_MOW_UINT32, 0, 8},
    {"rebase_size", 2, YX_MOW_UINT32, 0, 8},
    {"bind_off", 3, YX_MOW_UINT32, 0, 8},
    {"bind_size", 4, YX_MOW_UINT32, 0, 8},
    {"weak_bind_off", 5, YX_MOW_UINT32, 0, 8},
    {"weak_bind_size", 6, YX_MOW_UINT32, 0, 8},
    {"lazy_bind_off", 7, YX_MOW_UINT32, 0, 8},
    {"lazy_bind_size", 8, YX_MOW_UINT32, 0, 8},
    {"export_off", 9, YX_MOW_UINT32, 0, 8},
    {"export_size", 10, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_Dylib[] = {
    {"name", 1, YX_MOW_STRING, 0, 28},
    {"timestamp", 2, YX_MOW_UINT32, 0, 24},
    {"compatibility_version", 3, YX_MOW_STRING, 0, 24},
    {"current_version", 4, YX_MOW_STRING, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_macho_Dysymtab[] = {
    {"ilocalsym", 3, YX_MOW_UINT32, 0, 8},
    {"nlocalsym", 4, YX_MOW_UINT32, 0, 8},
    {"iextdefsym", 5, YX_MOW_UINT32, 0, 8},
    {"nextdefsym", 6, YX_MOW_UINT32, 0, 8},
    {"iundefsym", 7, YX_MOW_UINT32, 0, 8},
    {"nundefsym", 8, YX_MOW_UINT32, 0, 8},
    {"tocoff", 9, YX_MOW_UINT32, 0, 8},
    {"ntoc", 10, YX_MOW_UINT32, 0, 8},
    {"modtaboff", 11, YX_MOW_UINT32, 0, 8},
    {"nmodtab", 12, YX_MOW_UINT32, 0, 8},
    {"extrefsymoff", 13, YX_MOW_UINT32, 0, 8},
    {"nextrefsyms", 14, YX_MOW_UINT32, 0, 8},
    {"indirectsymoff", 15, YX_MOW_UINT32, 0, 8},
    {"nindirectsyms", 16, YX_MOW_UINT32, 0, 8},
    {"extreloff", 17, YX_MOW_UINT32, 0, 8},
    {"nextrel", 18, YX_MOW_UINT32, 0, 8},
    {"locreloff", 19, YX_MOW_UINT32, 0, 8},
    {"nlocrel", 20, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_FatArch[] = {
    {"cputype", 1, YX_MOW_UINT32, 0, 8},
    {"cpusubtype", 2, YX_MOW_UINT32, 0, 8},
    {"offset", 3, YX_MOW_INT64, 0, 8},
    {"size", 4, YX_MOW_INT64, 0, 8},
    {"align", 5, YX_MOW_UINT32, 0, 8},
    {"reserved", 6, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_File[] = {
    {"magic", 1, YX_MOW_UINT32, 0, 8},
    {"cputype", 2, YX_MOW_UINT32, 0, 8},
    {"cpusubtype", 3, YX_MOW_UINT32, 0, 8},
    {"filetype", 4, YX_MOW_UINT32, 0, 8},
    {"ncmds", 5, YX_MOW_UINT32, 0, 8},
    {"sizeofcmds", 6, YX_MOW_UINT32, 0, 8},
    {"flags", 7, YX_MOW_UINT32, 0, 8},
    {"reserved", 8, YX_MOW_UINT32, 0, 8},
    {"number_of_segments", 9, YX_MOW_INT64, 0, 8},
    {"dynamic_linker", 10, YX_MOW_STRING, 0, 12},
    {"entry_point", 11, YX_MOW_INT64, 0, 8},
    {"stack_size", 12, YX_MOW_INT64, 0, 8},
    {"source_version", 13, YX_MOW_STRING, 0, 8},
    {"segments", 14, YX_MOW_MESSAGE, 40, 1},
    {"dylibs", 15, YX_MOW_MESSAGE, 31, 1},
    {"rpaths", 16, YX_MOW_STRING, 0, 5},
    {"entitlements", 17, YX_MOW_STRING, 0, 1},
    {"symtab", 18, YX_MOW_MESSAGE, 41, 8},
    {"dysymtab", 19, YX_MOW_MESSAGE, 32, 8},
    {"dyld_info", 20, YX_MOW_MESSAGE, 30, 8},
    {"code_signature_data", 21, YX_MOW_MESSAGE, 35, 8},
    {"certificates", 22, YX_MOW_MESSAGE, 29, 1},
    {"uuid", 23, YX_MOW_STRING, 0, 8},
    {"build_version", 24, YX_MOW_MESSAGE, 28, 8},
    {"min_version", 25, YX_MOW_MESSAGE, 37, 8},
    {"exports", 26, YX_MOW_STRING, 0, 1},
    {"imports", 27, YX_MOW_STRING, 0, 1},
    {"linker_options", 28, YX_MOW_STRING, 0, 5},
};
static const yx_mo_wire_field yx_mo_fields_macho_LinkedItData[] = {
    {"dataoff", 1, YX_MOW_UINT32, 0, 8},
    {"datasize", 2, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_Macho[] = {
    {"magic", 1, YX_MOW_UINT32, 0, 8},
    {"cputype", 2, YX_MOW_UINT32, 0, 8},
    {"cpusubtype", 3, YX_MOW_UINT32, 0, 8},
    {"filetype", 4, YX_MOW_UINT32, 0, 8},
    {"ncmds", 5, YX_MOW_UINT32, 0, 8},
    {"sizeofcmds", 6, YX_MOW_UINT32, 0, 8},
    {"flags", 7, YX_MOW_UINT32, 0, 8},
    {"reserved", 8, YX_MOW_UINT32, 0, 8},
    {"number_of_segments", 9, YX_MOW_INT64, 0, 8},
    {"dynamic_linker", 10, YX_MOW_STRING, 0, 12},
    {"entry_point", 11, YX_MOW_INT64, 0, 8},
    {"stack_size", 12, YX_MOW_INT64, 0, 8},
    {"source_version", 13, YX_MOW_STRING, 0, 8},
    {"symtab", 14, YX_MOW_MESSAGE, 41, 8},
    {"dysymtab", 15, YX_MOW_MESSAGE, 32, 8},
    {"code_signature_data", 16, YX_MOW_MESSAGE, 35, 8},
    {"segments", 17, YX_MOW_MESSAGE, 40, 1},
    {"dylibs", 18, YX_MOW_MESSAGE, 31, 1},
    {"dyld_info", 19, YX_MOW_MESSAGE, 30, 8},
    {"rpaths", 20, YX_MOW_STRING, 0, 5},
    {"entitlements", 21, YX_MOW_STRING, 0, 1},
    {"certificates", 22, YX_MOW_MESSAGE, 29, 1},
    {"uuid", 23, YX_MOW_STRING, 0, 8},
    {"build_version", 24, YX_MOW_MESSAGE, 28, 8},
    {"min_version", 25, YX_MOW_MESSAGE, 37, 8},
    {"exports", 26, YX_MOW_STRING, 0, 1},
    {"imports", 27, YX_MOW_STRING, 0, 1},
    {"linker_options", 28, YX_MOW_STRING, 0, 5},
    {"fat_magic", 29, YX_MOW_UINT32, 0, 8},
    {"nfat_arch", 30, YX_MOW_UINT32, 0, 8},
    {"fat_arch", 31, YX_MOW_MESSAGE, 33, 1},
    {"file", 32, YX_MOW_MESSAGE, 34, 1},
};
static const yx_mo_wire_field yx_mo_fields_macho_MinVersion[] = {
    {"device", 1, YX_MOW_INT32, 0, 8},
    {"version", 2, YX_MOW_STRING, 0, 8},
    {"sdk", 3, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_Nlist[] = {
    {"n_strx", 1, YX_MOW_UINT32, 0, 8},
    {"n_type", 2, YX_MOW_UINT32, 0, 8},
    {"n_sect", 3, YX_MOW_UINT32, 0, 8},
    {"n_desc", 4, YX_MOW_UINT32, 0, 8},
    {"n_value", 5, YX_MOW_INT64, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_Section[] = {
    {"segname", 1, YX_MOW_STRING, 0, 12},
    {"sectname", 2, YX_MOW_STRING, 0, 12},
    {"addr", 3, YX_MOW_INT64, 0, 8},
    {"size", 4, YX_MOW_INT64, 0, 8},
    {"offset", 5, YX_MOW_UINT32, 0, 8},
    {"align", 6, YX_MOW_UINT32, 0, 8},
    {"reloff", 7, YX_MOW_UINT32, 0, 8},
    {"nreloc", 8, YX_MOW_UINT32, 0, 8},
    {"flags", 9, YX_MOW_UINT32, 0, 8},
    {"reserved1", 10, YX_MOW_UINT32, 0, 8},
    {"reserved2", 11, YX_MOW_UINT32, 0, 8},
    {"reserved3", 12, YX_MOW_UINT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_macho_Segment[] = {
    {"segname", 3, YX_MOW_STRING, 0, 12},
    {"vmaddr", 4, YX_MOW_INT64, 0, 8},
    {"vmsize", 5, YX_MOW_INT64, 0, 8},
    {"fileoff", 6, YX_MOW_INT64, 0, 8},
    {"filesize", 7, YX_MOW_INT64, 0, 8},
    {"maxprot", 8, YX_MOW_UINT32, 0, 8},
    {"initprot", 9, YX_MOW_UINT32, 0, 8},
    {"nsects", 10, YX_MOW_UINT32, 0, 8},
    {"flags", 11, YX_MOW_UINT32, 0, 8},
    {"sections", 12, YX_MOW_MESSAGE, 39, 1},
};
static const yx_mo_wire_field yx_mo_fields_macho_Symtab[] = {
    {"symoff", 1, YX_MOW_UINT32, 0, 8},
    {"nsyms", 2, YX_MOW_UINT32, 0, 8},
    {"stroff", 3, YX_MOW_UINT32, 0, 8},
    {"strsize", 4, YX_MOW_UINT32, 0, 8},
    {"entries", 5, YX_MOW_STRING, 0, 5},
    {"nlists", 6, YX_MOW_MESSAGE, 38, 1},
};
static const yx_mo_wire_field yx_mo_fields_olecf_Olecf[] = {
    {"is_olecf", 1, YX_MOW_BOOL, 0, 24},
    {"streams", 2, YX_MOW_MESSAGE, 43, 1},
};
static const yx_mo_wire_field yx_mo_fields_olecf_Stream[] = {
    {"name", 1, YX_MOW_STRING, 0, 24},
    {"type", 2, YX_MOW_INT32, 0, 24},
    {"size", 3, YX_MOW_INT64, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_Certificate[] = {
    {"issuer", 1, YX_MOW_STRING, 0, 8},
    {"subject", 2, YX_MOW_STRING, 0, 8},
    {"thumbprint", 3, YX_MOW_STRING, 0, 8},
    {"version", 4, YX_MOW_INT64, 0, 8},
    {"algorithm", 5, YX_MOW_STRING, 0, 8},
    {"algorithm_oid", 6, YX_MOW_STRING, 0, 8},
    {"serial", 7, YX_MOW_STRING, 0, 8},
    {"not_before", 8, YX_MOW_INT64, 0, 8},
    {"not_after", 9, YX_MOW_INT64, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_pe_CounterSignature[] = {
    {"verified", 1, YX_MOW_BOOL, 0, 8},
    {"sign_time", 2, YX_MOW_INT64, 0, 8},
    {"digest", 12, YX_MOW_STRING, 0, 8},
    {"digest_alg", 3, YX_MOW_STRING, 0, 8},
    {"chain", 4, YX_MOW_MESSAGE, 44, 1},
};
static const yx_mo_wire_field yx_mo_fields_pe_DirEntry[] = {
    {"virtual_address", 1, YX_MOW_UINT32, 0, 24},
    {"size", 2, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_Export[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"ordinal", 2, YX_MOW_UINT32, 0, 24},
    {"rva", 3, YX_MOW_UINT32, 0, 24},
    {"offset", 4, YX_MOW_UINT32, 0, 8},
    {"forward_name", 5, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_pe_Function[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"ordinal", 2, YX_MOW_UINT32, 0, 8},
    {"rva", 3, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_Import[] = {
    {"library_name", 1, YX_MOW_STRING, 0, 24},
    {"number_of_functions", 2, YX_MOW_INT64, 0, 24},
    {"functions", 3, YX_MOW_MESSAGE, 48, 1},
};
static const yx_mo_wire_field yx_mo_fields_pe_KeyValue[] = {
    {"key", 1, YX_MOW_STRING, 0, 24},
    {"value", 2, YX_MOW_STRING, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_Overlay[] = {
    {"offset", 1, YX_MOW_INT64, 0, 24},
    {"size", 2, YX_MOW_INT64, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_PE[] = {
    {"is_pe", 1, YX_MOW_BOOL, 0, 24},
    {"machine", 2, YX_MOW_INT32, 0, 8},
    {"subsystem", 3, YX_MOW_INT32, 0, 8},
    {"os_version", 4, YX_MOW_MESSAGE, 60, 8},
    {"subsystem_version", 5, YX_MOW_MESSAGE, 60, 8},
    {"image_version", 6, YX_MOW_MESSAGE, 60, 8},
    {"linker_version", 7, YX_MOW_MESSAGE, 60, 8},
    {"opthdr_magic", 8, YX_MOW_INT32, 0, 8},
    {"characteristics", 9, YX_MOW_UINT32, 0, 8},
    {"dll_characteristics", 10, YX_MOW_UINT32, 0, 8},
    {"timestamp", 11, YX_MOW_UINT32, 0, 8},
    {"image_base", 12, YX_MOW_INT64, 0, 8},
    {"checksum", 13, YX_MOW_UINT32, 0, 8},
    {"base_of_code", 14, YX_MOW_UINT32, 0, 8},
    {"base_of_data", 15, YX_MOW_UINT32, 0, 8},
    {"entry_point", 16, YX_MOW_UINT32, 0, 8},
    {"entry_point_raw", 17, YX_MOW_UINT32, 0, 8},
    {"dll_name", 18, YX_MOW_STRING, 0, 8},
    {"export_timestamp", 19, YX_MOW_UINT32, 0, 8},
    {"section_alignment", 20, YX_MOW_UINT32, 0, 8},
    {"file_alignment", 21, YX_MOW_UINT32, 0, 8},
    {"loader_flags", 22, YX_MOW_UINT32, 0, 8},
    {"size_of_optional_header", 23, YX_MOW_UINT32, 0, 8},
    {"size_of_code", 24, YX_MOW_UINT32, 0, 8},
    {"size_of_initialized_data", 25, YX_MOW_UINT32, 0, 8},
    {"size_of_uninitialized_data", 26, YX_MOW_UINT32, 0, 8},
    {"size_of_image", 27, YX_MOW_UINT32, 0, 8},
    {"size_of_headers", 28, YX_MOW_UINT32, 0, 8},
    {"size_of_stack_reserve", 29, YX_MOW_INT64, 0, 8},
    {"size_of_stack_commit", 30, YX_MOW_INT64, 0, 8},
    {"size_of_heap_reserve", 31, YX_MOW_INT64, 0, 8},
    {"size_of_heap_commit", 32, YX_MOW_INT64, 0, 8},
    {"pointer_to_symbol_table", 33, YX_MOW_UINT32, 0, 8},
    {"win32_version_value", 34, YX_MOW_UINT32, 0, 8},
    {"number_of_symbols", 35, YX_MOW_UINT32, 0, 8},
    {"number_of_rva_and_sizes", 36, YX_MOW_UINT32, 0, 8},
    {"number_of_sections", 37, YX_MOW_UINT32, 0, 8},
    {"number_of_imported_functions", 38, YX_MOW_INT64, 0, 8},
    {"number_of_delayed_imported_functions", 39, YX_MOW_INT64, 0, 8},
    {"number_of_resources", 40, YX_MOW_INT64, 0, 8},
    {"number_of_version_infos", 41, YX_MOW_INT64, 0, 8},
    {"number_of_imports", 42, YX_MOW_INT64, 0, 8},
    {"number_of_delayed_imports", 43, YX_MOW_INT64, 0, 8},
    {"number_of_exports", 44, YX_MOW_INT64, 0, 8},
    {"number_of_signatures", 45, YX_MOW_INT64, 0, 8},
    {"version_info", 46, YX_MOW_MESSAGE, 53, 3},
    {"version_info_list", 47, YX_MOW_MESSAGE, 50, 1},
    {"rich_signature", 48, YX_MOW_MESSAGE, 55, 8},
    {"pdb_path", 49, YX_MOW_STRING, 0, 12},
    {"sections", 50, YX_MOW_MESSAGE, 57, 1},
    {"data_directories", 51, YX_MOW_MESSAGE, 46, 1},
    {"resource_timestamp", 52, YX_MOW_INT64, 0, 8},
    {"resource_version", 53, YX_MOW_MESSAGE, 60, 8},
    {"resources", 54, YX_MOW_MESSAGE, 54, 1},
    {"import_details", 55, YX_MOW_MESSAGE, 49, 1},
    {"delayed_import_details", 56, YX_MOW_MESSAGE, 49, 1},
    {"export_details", 57, YX_MOW_MESSAGE, 47, 1},
    {"is_signed", 58, YX_MOW_BOOL, 0, 8},
    {"signatures", 59, YX_MOW_MESSAGE, 58, 1},
    {"overlay", 60, YX_MOW_MESSAGE, 51, 8},
};
static const yx_mo_wire_field yx_mo_fields_pe_PE_VersionInfoEntry[] = {
    {"key", 1, YX_MOW_STRING, 0, 0},
    {"value", 2, YX_MOW_STRING, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_pe_Resource[] = {
    {"length", 1, YX_MOW_UINT32, 0, 24},
    {"rva", 2, YX_MOW_UINT32, 0, 24},
    {"offset", 3, YX_MOW_UINT32, 0, 8},
    {"type", 4, YX_MOW_INT32, 0, 8},
    {"id", 5, YX_MOW_UINT32, 0, 8},
    {"language", 6, YX_MOW_UINT32, 0, 8},
    {"type_string", 7, YX_MOW_STRING, 0, 12},
    {"name_string", 8, YX_MOW_STRING, 0, 12},
    {"language_string", 9, YX_MOW_STRING, 0, 12},
};
static const yx_mo_wire_field yx_mo_fields_pe_RichSignature[] = {
    {"offset", 1, YX_MOW_UINT32, 0, 24},
    {"length", 2, YX_MOW_UINT32, 0, 24},
    {"key", 3, YX_MOW_UINT32, 0, 24},
    {"raw_data", 4, YX_MOW_STRING, 0, 28},
    {"clear_data", 5, YX_MOW_STRING, 0, 28},
    {"tools", 6, YX_MOW_MESSAGE, 56, 1},
};
static const yx_mo_wire_field yx_mo_fields_pe_RichTool[] = {
    {"toolid", 1, YX_MOW_UINT32, 0, 24},
    {"version", 2, YX_MOW_UINT32, 0, 24},
    {"times", 3, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_Section[] = {
    {"name", 1, YX_MOW_STRING, 0, 28},
    {"full_name", 2, YX_MOW_STRING, 0, 28},
    {"characteristics", 3, YX_MOW_UINT32, 0, 24},
    {"raw_data_size", 4, YX_MOW_UINT32, 0, 24},
    {"raw_data_offset", 5, YX_MOW_UINT32, 0, 24},
    {"virtual_address", 6, YX_MOW_UINT32, 0, 24},
    {"virtual_size", 7, YX_MOW_UINT32, 0, 24},
    {"pointer_to_relocations", 8, YX_MOW_UINT32, 0, 24},
    {"pointer_to_line_numbers", 9, YX_MOW_UINT32, 0, 24},
    {"number_of_relocations", 10, YX_MOW_UINT32, 0, 24},
    {"number_of_line_numbers", 11, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_pe_Signature[] = {
    {"subject", 1, YX_MOW_STRING, 0, 8},
    {"issuer", 2, YX_MOW_STRING, 0, 8},
    {"thumbprint", 3, YX_MOW_STRING, 0, 8},
    {"version", 4, YX_MOW_INT64, 0, 8},
    {"algorithm", 5, YX_MOW_STRING, 0, 8},
    {"algorithm_oid", 6, YX_MOW_STRING, 0, 8},
    {"serial", 7, YX_MOW_STRING, 0, 8},
    {"not_before", 8, YX_MOW_INT64, 0, 8},
    {"not_after", 9, YX_MOW_INT64, 0, 8},
    {"verified", 10, YX_MOW_BOOL, 0, 8},
    {"digest_alg", 11, YX_MOW_STRING, 0, 8},
    {"digest", 12, YX_MOW_STRING, 0, 8},
    {"file_digest", 13, YX_MOW_STRING, 0, 8},
    {"number_of_certificates", 14, YX_MOW_INT64, 0, 8},
    {"number_of_countersignatures", 15, YX_MOW_INT64, 0, 8},
    {"signer_info", 16, YX_MOW_MESSAGE, 59, 8},
    {"certificates", 17, YX_MOW_MESSAGE, 44, 1},
    {"countersignatures", 18, YX_MOW_MESSAGE, 45, 1},
};
static const yx_mo_wire_field yx_mo_fields_pe_SignerInfo[] = {
    {"program_name", 1, YX_MOW_STRING, 0, 8},
    {"more_info", 2, YX_MOW_STRING, 0, 8},
    {"digest", 3, YX_MOW_STRING, 0, 8},
    {"digest_alg", 4, YX_MOW_STRING, 0, 8},
    {"chain", 5, YX_MOW_MESSAGE, 44, 1},
};
static const yx_mo_wire_field yx_mo_fields_pe_Version[] = {
    {"major", 1, YX_MOW_UINT32, 0, 24},
    {"minor", 2, YX_MOW_UINT32, 0, 24},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_NestedProto2[] = {
    {"nested_int32_zero", 1, YX_MOW_INT32, 0, 8},
    {"nested_int64_zero", 2, YX_MOW_INT64, 0, 8},
    {"nested_int32_one", 3, YX_MOW_INT32, 0, 8},
    {"nested_int64_one", 4, YX_MOW_INT64, 0, 8},
    {"nested_bool", 5, YX_MOW_BOOL, 0, 8},
    {"nested_string", 6, YX_MOW_STRING, 0, 8},
    {"nested_array_int64", 7, YX_MOW_INT64, 0, 1},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2[] = {
    {"int32_zero", 1, YX_MOW_INT32, 0, 24},
    {"int64_zero", 2, YX_MOW_INT64, 0, 24},
    {"sint32_zero", 3, YX_MOW_SINT32, 0, 24},
    {"sint64_zero", 4, YX_MOW_SINT64, 0, 24},
    {"uint32_zero", 5, YX_MOW_UINT32, 0, 24},
    {"uint64_zero", 6, YX_MOW_UINT64, 0, 24},
    {"fixed32_zero", 7, YX_MOW_FIXED32, 0, 24},
    {"fixed64_zero", 8, YX_MOW_FIXED64, 0, 24},
    {"sfixed32_zero", 9, YX_MOW_SFIXED32, 0, 24},
    {"sfixed64_zero", 10, YX_MOW_SFIXED64, 0, 24},
    {"float_zero", 11, YX_MOW_FLOAT, 0, 24},
    {"double_zero", 12, YX_MOW_DOUBLE, 0, 24},
    {"int32_one", 21, YX_MOW_INT32, 0, 24},
    {"int64_one", 22, YX_MOW_INT64, 0, 24},
    {"sint32_one", 23, YX_MOW_SINT32, 0, 24},
    {"sint64_one", 24, YX_MOW_SINT64, 0, 24},
    {"uint32_one", 25, YX_MOW_UINT32, 0, 24},
    {"uint64_one", 26, YX_MOW_UINT64, 0, 24},
    {"fixed32_one", 27, YX_MOW_FIXED32, 0, 24},
    {"fixed64_one", 28, YX_MOW_FIXED64, 0, 24},
    {"sfixed32_one", 29, YX_MOW_SFIXED32, 0, 24},
    {"sfixed64_one", 30, YX_MOW_SFIXED64, 0, 24},
    {"float_one", 31, YX_MOW_FLOAT, 0, 24},
    {"double_one", 32, YX_MOW_DOUBLE, 0, 24},
    {"int32_undef", 41, YX_MOW_INT32, 0, 8},
    {"int64_undef", 42, YX_MOW_INT64, 0, 8},
    {"sint32_undef", 43, YX_MOW_SINT32, 0, 8},
    {"sint64_undef", 44, YX_MOW_SINT64, 0, 8},
    {"uint32_undef", 45, YX_MOW_UINT32, 0, 8},
    {"uint64_undef", 46, YX_MOW_UINT64, 0, 8},
    {"fixed32_undef", 47, YX_MOW_FIXED32, 0, 8},
    {"fixed64_undef", 48, YX_MOW_FIXED64, 0, 8},
    {"sfixed32_undef", 49, YX_MOW_SFIXED32, 0, 8},
    {"sfixed64_undef", 50, YX_MOW_SFIXED64, 0, 8},
    {"float_undef", 51, YX_MOW_FLOAT, 0, 8},
    {"double_undef", 52, YX_MOW_DOUBLE, 0, 8},
    {"string_foo", 61, YX_MOW_STRING, 0, 24},
    {"string_bar", 62, YX_MOW_STRING, 0, 24},
    {"string_undef", 63, YX_MOW_STRING, 0, 8},
    {"bytes_foo", 64, YX_MOW_STRING, 0, 28},
    {"bytes_bar", 65, YX_MOW_STRING, 0, 28},
    {"bytes_raw", 66, YX_MOW_STRING, 0, 28},
    {"bytes_undef", 67, YX_MOW_STRING, 0, 12},
    {"enumeration", 100, YX_MOW_INT32, 0, 8},
    {"nested", 102, YX_MOW_MESSAGE, 61, 8},
    {"array_int64", 150, YX_MOW_INT64, 0, 1},
    {"array_float", 151, YX_MOW_FLOAT, 0, 1},
    {"array_bool", 152, YX_MOW_BOOL, 0, 1},
    {"array_string", 153, YX_MOW_STRING, 0, 1},
    {"array_struct", 154, YX_MOW_MESSAGE, 61, 1},
    {"map_string_struct", 200, YX_MOW_MESSAGE, 72, 3},
    {"map_string_int64", 201, YX_MOW_MESSAGE, 70, 3},
    {"map_string_string", 202, YX_MOW_MESSAGE, 71, 3},
    {"map_string_bool", 203, YX_MOW_MESSAGE, 68, 3},
    {"map_string_float", 204, YX_MOW_MESSAGE, 69, 3},
    {"map_int64_struct", 300, YX_MOW_MESSAGE, 67, 3},
    {"map_int64_int64", 301, YX_MOW_MESSAGE, 65, 3},
    {"map_int64_string", 302, YX_MOW_MESSAGE, 66, 3},
    {"map_int64_bool", 303, YX_MOW_MESSAGE, 63, 3},
    {"map_int64_float", 304, YX_MOW_MESSAGE, 64, 3},
    {"timestamp", 305, YX_MOW_INT64, 0, 8},
    {"bool_yara", 350, YX_MOW_BOOL, 0, 8},
    {"ignored", 351, YX_MOW_BOOL, 0, 40},
    {"file_size", 400, YX_MOW_UINT64, 0, 8},
    {"requires_foo_and_bar", 500, YX_MOW_UINT64, 0, 8},
    {"deprecated", 501, YX_MOW_STRING, 0, 8},
    {"metadata", 502, YX_MOW_STRING, 0, 12},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapInt64BoolEntry[] = {
    {"key", 1, YX_MOW_INT64, 0, 0},
    {"value", 2, YX_MOW_BOOL, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapInt64FloatEntry[] = {
    {"key", 1, YX_MOW_INT64, 0, 0},
    {"value", 2, YX_MOW_FLOAT, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapInt64Int64Entry[] = {
    {"key", 1, YX_MOW_INT64, 0, 0},
    {"value", 2, YX_MOW_INT64, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapInt64StringEntry[] = {
    {"key", 1, YX_MOW_INT64, 0, 0},
    {"value", 2, YX_MOW_STRING, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapInt64StructEntry[] = {
    {"key", 1, YX_MOW_INT64, 0, 0},
    {"value", 2, YX_MOW_MESSAGE, 61, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapStringBoolEntry[] = {
    {"key", 1, YX_MOW_STRING, 0, 0},
    {"value", 2, YX_MOW_BOOL, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapStringFloatEntry[] = {
    {"key", 1, YX_MOW_STRING, 0, 0},
    {"value", 2, YX_MOW_FLOAT, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapStringInt64Entry[] = {
    {"key", 1, YX_MOW_STRING, 0, 0},
    {"value", 2, YX_MOW_INT64, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapStringStringEntry[] = {
    {"key", 1, YX_MOW_STRING, 0, 0},
    {"value", 2, YX_MOW_STRING, 0, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto2_TestProto2_MapStringStructEntry[] = {
    {"key", 1, YX_MOW_STRING, 0, 0},
    {"value", 2, YX_MOW_MESSAGE, 61, 0},
};
static const yx_mo_wire_field yx_mo_fields_test_proto3_TestProto3[] = {
    {"int32_zero", 1, YX_MOW_INT32, 0, 0},
    {"int64_zero", 2, YX_MOW_INT64, 0, 0},
    {"sint32_zero", 3, YX_MOW_SINT32, 0, 0},
    {"sint64_zero", 4, YX_MOW_SINT64, 0, 0},
    {"uint32_zero", 5, YX_MOW_UINT32, 0, 0},
    {"uint64_zero", 6, YX_MOW_UINT64, 0, 0},
    {"fixed32_zero", 7, YX_MOW_FIXED32, 0, 0},
    {"fixed64_zero", 8, YX_MOW_FIXED64, 0, 0},
    {"sfixed32_zero", 9, YX_MOW_SFIXED32, 0, 0},
    {"sfixed64_zero", 10, YX_MOW_SFIXED64, 0, 0},
    {"float_zero", 11, YX_MOW_FLOAT, 0, 0},
    {"int32_one", 21, YX_MOW_INT32, 0, 0},
    {"int64_one", 22, YX_MOW_INT64, 0, 0},
    {"sint32_one", 23, YX_MOW_SINT32, 0, 0},
    {"sint64_one", 24, YX_MOW_SINT64, 0, 0},
    {"uint32_one", 25, YX_MOW_UINT32, 0, 0},
    {"uint64_one", 26, YX_MOW_UINT64, 0, 0},
    {"fixed32_one", 27, YX_MOW_FIXED32, 0, 0},
    {"fixed64_one", 28, YX_MOW_FIXED64, 0, 0},
    {"sfixed32_one", 29, YX_MOW_SFIXED32, 0, 0},
    {"sfixed64_one", 30, YX_MOW_SFIXED64, 0, 0},
    {"float_one", 31, YX_MOW_FLOAT, 0, 0},
    {"int32_undef", 41, YX_MOW_INT32, 0, 0},
    {"int64_undef", 42, YX_MOW_INT64, 0, 0},
    {"sint32_undef", 43, YX_MOW_SINT32, 0, 0},
    {"sint64_undef", 44, YX_MOW_SINT64, 0, 0},
    {"uint32_undef", 45, YX_MOW_UINT32, 0, 0},
    {"uint64_undef", 46, YX_MOW_UINT64, 0, 0},
    {"fixed32_undef", 47, YX_MOW_FIXED32, 0, 0},
    {"fixed64_undef", 48, YX_MOW_FIXED64, 0, 0},
    {"sfixed32_undef", 49, YX_MOW_SFIXED32, 0, 0},
    {"sfixed64_undef", 50, YX_MOW_SFIXED64, 0, 0},
    {"float_undef", 51, YX_MOW_FLOAT, 0, 0},
    {"bool_undef", 52, YX_MOW_BOOL, 0, 0},
    {"string_foo", 61, YX_MOW_STRING, 0, 0},
    {"string_bar", 62, YX_MOW_STRING, 0, 0},
    {"string_undef", 63, YX_MOW_STRING, 0, 0},
    {"bytes_foo", 64, YX_MOW_STRING, 0, 4},
    {"bytes_bar", 65, YX_MOW_STRING, 0, 4},
    {"bytes_undef", 66, YX_MOW_STRING, 0, 4},
};
static const yx_mo_wire_field yx_mo_fields_vba_Vba[] = {
    {"has_macros", 1, YX_MOW_BOOL, 0, 8},
    {"modules", 2, YX_MOW_MESSAGE, 75, 1},
    {"project_info", 5, YX_MOW_MESSAGE, 76, 8},
};
static const yx_mo_wire_field yx_mo_fields_vba_Vba_Module[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"type", 2, YX_MOW_INT32, 0, 8},
    {"code", 3, YX_MOW_STRING, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_vba_Vba_ProjectInfo[] = {
    {"name", 1, YX_MOW_STRING, 0, 8},
    {"version", 2, YX_MOW_STRING, 0, 8},
    {"references", 3, YX_MOW_STRING, 0, 1},
    {"module_count", 4, YX_MOW_INT32, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_zip_Entry[] = {
    {"file_path", 1, YX_MOW_STRING, 0, 8},
    {"compression", 2, YX_MOW_INT32, 0, 8},
    {"uncompressed_size", 3, YX_MOW_INT64, 0, 8},
    {"compressed_size", 4, YX_MOW_INT64, 0, 8},
};
static const yx_mo_wire_field yx_mo_fields_zip_Zip[] = {
    {"is_zip", 1, YX_MOW_BOOL, 0, 8},
    {"entries", 2, YX_MOW_MESSAGE, 77, 1},
};
static const yx_mo_wire_field yx_mo_fields_msi_Msi[] = {
    {"is_signed", 1, YX_MOW_BOOL, 0, 8},
    {"signatures", 2, YX_MOW_MESSAGE, 58, 1},
};
static const yx_mo_wire_message yx_mo_wire_messages[] = {
    {"crx.Crx", yx_mo_fields_crx_Crx, 16},
    {"crx.CrxSignature", yx_mo_fields_crx_CrxSignature, 2},
    {"dex.ClassItem", yx_mo_fields_dex_ClassItem, 4},
    {"dex.Dex", yx_mo_fields_dex_Dex, 9},
    {"dex.DexHeader", yx_mo_fields_dex_DexHeader, 13},
    {"dex.FieldItem", yx_mo_fields_dex_FieldItem, 3},
    {"dex.MapItem", yx_mo_fields_dex_MapItem, 4},
    {"dex.MapList", yx_mo_fields_dex_MapList, 2},
    {"dex.MethodItem", yx_mo_fields_dex_MethodItem, 3},
    {"dex.ProtoItem", yx_mo_fields_dex_ProtoItem, 4},
    {"dotnet.Assembly", yx_mo_fields_dotnet_Assembly, 3},
    {"dotnet.AssemblyRef", yx_mo_fields_dotnet_AssemblyRef, 3},
    {"dotnet.Class", yx_mo_fields_dotnet_Class, 13},
    {"dotnet.Dotnet", yx_mo_fields_dotnet_Dotnet, 24},
    {"dotnet.Method", yx_mo_fields_dotnet_Method, 11},
    {"dotnet.Param", yx_mo_fields_dotnet_Param, 2},
    {"dotnet.Resource", yx_mo_fields_dotnet_Resource, 3},
    {"dotnet.Stream", yx_mo_fields_dotnet_Stream, 3},
    {"dotnet.Version", yx_mo_fields_dotnet_Version, 4},
    {"elf.Dyn", yx_mo_fields_elf_Dyn, 2},
    {"elf.ELF", yx_mo_fields_elf_ELF, 18},
    {"elf.Section", yx_mo_fields_elf_Section, 6},
    {"elf.Segment", yx_mo_fields_elf_Segment, 8},
    {"elf.Sym", yx_mo_fields_elf_Sym, 7},
    {"lnk.Lnk", yx_mo_fields_lnk_Lnk, 22},
    {"lnk.ShellItem", yx_mo_fields_lnk_ShellItem, 8},
    {"lnk.TrackerData", yx_mo_fields_lnk_TrackerData, 6},
    {"macho.BuildTool", yx_mo_fields_macho_BuildTool, 2},
    {"macho.BuildVersion", yx_mo_fields_macho_BuildVersion, 5},
    {"macho.Certificate", yx_mo_fields_macho_Certificate, 3},
    {"macho.DyldInfo", yx_mo_fields_macho_DyldInfo, 10},
    {"macho.Dylib", yx_mo_fields_macho_Dylib, 4},
    {"macho.Dysymtab", yx_mo_fields_macho_Dysymtab, 18},
    {"macho.FatArch", yx_mo_fields_macho_FatArch, 6},
    {"macho.File", yx_mo_fields_macho_File, 28},
    {"macho.LinkedItData", yx_mo_fields_macho_LinkedItData, 2},
    {"macho.Macho", yx_mo_fields_macho_Macho, 32},
    {"macho.MinVersion", yx_mo_fields_macho_MinVersion, 3},
    {"macho.Nlist", yx_mo_fields_macho_Nlist, 5},
    {"macho.Section", yx_mo_fields_macho_Section, 12},
    {"macho.Segment", yx_mo_fields_macho_Segment, 10},
    {"macho.Symtab", yx_mo_fields_macho_Symtab, 6},
    {"olecf.Olecf", yx_mo_fields_olecf_Olecf, 2},
    {"olecf.Stream", yx_mo_fields_olecf_Stream, 3},
    {"pe.Certificate", yx_mo_fields_pe_Certificate, 9},
    {"pe.CounterSignature", yx_mo_fields_pe_CounterSignature, 5},
    {"pe.DirEntry", yx_mo_fields_pe_DirEntry, 2},
    {"pe.Export", yx_mo_fields_pe_Export, 5},
    {"pe.Function", yx_mo_fields_pe_Function, 3},
    {"pe.Import", yx_mo_fields_pe_Import, 3},
    {"pe.KeyValue", yx_mo_fields_pe_KeyValue, 2},
    {"pe.Overlay", yx_mo_fields_pe_Overlay, 2},
    {"pe.PE", yx_mo_fields_pe_PE, 60},
    {"pe.PE.VersionInfoEntry", yx_mo_fields_pe_PE_VersionInfoEntry, 2},
    {"pe.Resource", yx_mo_fields_pe_Resource, 9},
    {"pe.RichSignature", yx_mo_fields_pe_RichSignature, 6},
    {"pe.RichTool", yx_mo_fields_pe_RichTool, 3},
    {"pe.Section", yx_mo_fields_pe_Section, 11},
    {"pe.Signature", yx_mo_fields_pe_Signature, 18},
    {"pe.SignerInfo", yx_mo_fields_pe_SignerInfo, 5},
    {"pe.Version", yx_mo_fields_pe_Version, 2},
    {"test_proto2.NestedProto2", yx_mo_fields_test_proto2_NestedProto2, 7},
    {"test_proto2.TestProto2", yx_mo_fields_test_proto2_TestProto2, 67},
    {"test_proto2.TestProto2.MapInt64BoolEntry", yx_mo_fields_test_proto2_TestProto2_MapInt64BoolEntry, 2},
    {"test_proto2.TestProto2.MapInt64FloatEntry", yx_mo_fields_test_proto2_TestProto2_MapInt64FloatEntry, 2},
    {"test_proto2.TestProto2.MapInt64Int64Entry", yx_mo_fields_test_proto2_TestProto2_MapInt64Int64Entry, 2},
    {"test_proto2.TestProto2.MapInt64StringEntry", yx_mo_fields_test_proto2_TestProto2_MapInt64StringEntry, 2},
    {"test_proto2.TestProto2.MapInt64StructEntry", yx_mo_fields_test_proto2_TestProto2_MapInt64StructEntry, 2},
    {"test_proto2.TestProto2.MapStringBoolEntry", yx_mo_fields_test_proto2_TestProto2_MapStringBoolEntry, 2},
    {"test_proto2.TestProto2.MapStringFloatEntry", yx_mo_fields_test_proto2_TestProto2_MapStringFloatEntry, 2},
    {"test_proto2.TestProto2.MapStringInt64Entry", yx_mo_fields_test_proto2_TestProto2_MapStringInt64Entry, 2},
    {"test_proto2.TestProto2.MapStringStringEntry", yx_mo_fields_test_proto2_TestProto2_MapStringStringEntry, 2},
    {"test_proto2.TestProto2.MapStringStructEntry", yx_mo_fields_test_proto2_TestProto2_MapStringStructEntry, 2},
    {"test_proto3.TestProto3", yx_mo_fields_test_proto3_TestProto3, 40},
    {"vba.Vba", yx_mo_fields_vba_Vba, 3},
    {"vba.Vba.Module", yx_mo_fields_vba_Vba_Module, 3},
    {"vba.Vba.ProjectInfo", yx_mo_fields_vba_Vba_ProjectInfo, 4},
    {"zip.Entry", yx_mo_fields_zip_Entry, 4},
    {"zip.Zip", yx_mo_fields_zip_Zip, 2},
    {"msi.Msi", yx_mo_fields_msi_Msi, 2},
};
static const yx_mo_module yx_mo_modules[] = {
    {"pe", "pe.PE", 52},
    {"elf", "elf.ELF", 20},
    {"macho", "macho.Macho", 36},
    {"dotnet", "dotnet.Dotnet", 13},
    {"dex", "dex.Dex", 3},
    {"test_proto2", "test_proto2.TestProto2", 62},
    {"test_proto3", "test_proto3.TestProto3", 73},
    {"lnk", "lnk.Lnk", 24},
    {"crx", "crx.Crx", 0},
    {"zip", "zip.Zip", 78},
    {"olecf", "olecf.Olecf", 42},
    {"vba", "vba.Vba", 74},
    {"msi", "msi.Msi", 79},
};
