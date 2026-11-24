cmake_minimum_required(VERSION 3.16)

project(xxyara VERSION 0.1.0 LANGUAGES C)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(_xxyara_top_level OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(_xxyara_top_level ON)
endif()

# The binaries built from this tree (xxyara.dll, yr.exe) import nothing but
# KERNEL32: MSVC links the C runtime statically (/MT). Everything compiled into
# one binary must use the same runtime, so the static library and the tests
# follow. A parent project that adds xxyara with add_subdirectory keeps its own
# choice (CMAKE_MSVC_RUNTIME_LIBRARY), and so does an explicit -D on the command line.
if(MSVC AND _xxyara_top_level AND NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

option(XXYARA_BUILD_CLI "Build the xxyara command-line tool" ON)
option(XXYARA_BUILD_CONSOLE "Build xxyara, the console application: yr's commands and output under its own name and banner" ${_xxyara_top_level})
option(XXYARA_BUILD_TESTS "Build xxyara tests" OFF)
option(XXYARA_BUILD_SHARED "Build the shared library (xxyara.dll / libxxyara.so) next to the static one" ${_xxyara_top_level})
option(XXYARA_BUILD_EXAMPLES "Build the C and C++ examples in examples/" ${_xxyara_top_level})
option(XXYARA_ENABLE_OLECF "Enable the experimental YARA-X olecf module" OFF)
option(XXYARA_ENABLE_VBA "Enable the experimental YARA-X vba module" OFF)
option(XXYARA_ENABLE_MAGIC "Enable the optional YARA-X magic module" OFF)
option(XXYARA_ENABLE_MSI "Enable the experimental YARA-X msi module" OFF)
option(XXYARA_ENABLE_TEST_PROTO "Enable the test-only test_proto2 and test_proto3 modules" OFF)
option(XXYARA_ENABLE_PROFILING "Enable YARA-X C API rule profiling" OFF)

# CRT-free build: xxyara.dll, yr.exe, the C examples and the tests link no
# Microsoft C runtime at all (no ucrt/vcruntime/msvcrt DLL, no static
# libucrt/libvcruntime/libcmt) and import nothing but KERNEL32. The C runtime
# they call by its standard names comes from xxfclib: the portable cores in
# src/crt (UCRT-identical printf, strtod, qsort, ...) and the Windows layer in
# src/crt/platforms (stdio, entry points, TLS directory), built here as the
# static library xxyara_crt. The static xxyara.lib is compiled /GS- /Zl, so a
# /NODEFAULTLIB consumer links it with xxyara_crt and a hosted consumer (the
# C++ example) links it with its own C runtime. OFF keeps the static Microsoft
# runtime (/MT); subproject builds are not affected.
set(_xxyara_no_crt_default OFF)
if(MSVC AND _xxyara_top_level AND CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^(x64|X64|AMD64)$")
    set(_xxyara_no_crt_default ON)
endif()
option(XXYARA_NO_CRT "Link xxyara.dll, yr.exe, the C examples and the tests without the Microsoft C runtime (MSVC x64)"
    ${_xxyara_no_crt_default})
if(XXYARA_NO_CRT)
    if(NOT MSVC OR NOT CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^(x64|X64|AMD64|X86|x86)$")
        message(FATAL_ERROR "XXYARA_NO_CRT needs MSVC for x64 or x86")
    endif()
    enable_language(ASM_MASM)
    # No security-cookie checks (they live in the C runtime) and no default
    # library records in the C objects.
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/GS-> $<$<COMPILE_LANGUAGE:C>:/Zl>)
    string(REGEX REPLACE "[/-](RTC[1csu]|GZ)" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
endif()
set(XXYARA_REFERENCE_YR "" CACHE FILEPATH
    "Optional official yr executable used for CLI differential tests")
set(XXYARA_REFERENCE_VBA_YR "" CACHE FILEPATH
    "Optional official yr executable built with VBA for differential tests")
set(XXYARA_REFERENCE_DEFAULT_YR "" CACHE FILEPATH
    "Optional official default-feature yr for feature-independent reference tests (defaults to XXYARA_REFERENCE_YR)")
set(XXYARA_XXFCLIB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../xxfclib"
    CACHE PATH "Path to the xxfclib source tree")

# The upstream xxfclib target compiles thousands of format readers. xxyara
# uses its byte search, I/O, hash, XML, regex, codepage and Deflate APIs. Build their
# focused source closure when a parent has not already provided xxfclib.
if(NOT TARGET xxfclib::xxfclib)
    if(NOT EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/include/xxfclib/data/xx_data.h")
        message(FATAL_ERROR "xxfclib was not found at ${XXYARA_XXFCLIB_SOURCE_DIR}")
    endif()

    set(_xxfc_sources
        src/algo/md5/xx_md5.c
        src/algo/md2/xx_md2.c
        src/algo/sha512/xx_sha512.c
        src/algo/bignum/xx_bignum.c
        src/algo/rsa/xx_rsa.c
        src/algo/ec/xx_ec.c
        src/algo/dsa/xx_dsa.c
        src/algo/pki/xx_pki_verify.c
        src/algo/asn1/xx_asn1.c
        src/algo/x509/xx_x509.c
        src/algo/pkcs7/xx_pkcs7.c
        src/algo/pkcs7/xx_authenticode.c
        src/algo/pkcs7/xx_tsp.c
        src/algo/sha/xx_sha.c
        src/algo/sha/xx_sha_simd.c
        src/algo/literal/xx_literal.c
        src/algo/literal/xx_literal_ssse3.c
        src/algo/literal/xx_literal_avx2.c
        src/algo/literal_nocase/xx_literal_nocase.c
        src/algo/crc/xx_crc.c
        src/algo/crc/xx_crc8.c
        src/algo/crc/xx_crc16.c
        src/algo/crc/xx_crc32.c
        src/algo/crc/xx_crc64.c
        src/algo/crc/xx_crc_io.c
        src/algo/crc/platforms/xx_crc32_arm_pmull.c
        src/algo/crc/platforms/xx_crc32_arm.c
        src/algo/crc/platforms/xx_crc32c_sse42.c
        src/algo/crc/platforms/xx_crc64_sse2.c
        src/algo/crc/platforms/xx_crc64_avx2.c
        src/algo/crc/platforms/xx_crc64_vpclmul.c
        src/algo/deflate/xx_deflate.c
        src/algo/deflate/xx_deflate_dec.c
        src/algo/deflate/xx_deflate_enc.c
        src/algo/deflate/platforms/xx_deflate_sse2.c
        src/algo/deflate/platforms/xx_deflate_avx2.c
        src/algo/deflate/platforms/xx_deflate_neon.c
        src/codepages/xx_codepage_whatwg.c
        src/data/xx_data_raw.c
        src/data/xx_data_io.c
        src/data/xx_pd.c
        src/data/platforms/xx_data_sse2.c
        src/data/platforms/xx_data_avx2.c
        src/io/xx_io.c
        src/io/xx_io_file.c
        src/io/xx_io_mem.c
        src/io/xx_io_memory_only.c
        src/io/xx_io_sub.c
        src/json/xx_json.c
        src/xml/xx_xml.c
        src/regex/xx_regex.c
        src/regex/xx_regex_search.c
        src/regex/xx_regex_unicode.c
        src/threads/xx_threads.c
        src/global/xx_global.c
        src/global/platforms/xx_global_cpu.c
        src/memory/xx_memory.c
        src/memory/xx_memory_rt.c
        src/memory/platforms/xx_memory_sse2.c
        src/memory/platforms/xx_memory_avx2.c
        src/rt/xx_rt.c
        src/rt/xx_rt_fp.c
        src/rt/xx_rt_math.c
        src/strings/xx_string.c)
    # Indexed parallel loop for the compiled-rules loader (opt4_load lane).
    list(APPEND _xxfc_sources src/threads/xx_parallel.c)
    # regex-syntax 0.8.11's Unicode 16.0.0 regex tables (property classes,
    # Perl classes, simple case folding); added in the rxuni lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/regex/xx_regex_unicode16.c")
        list(APPEND _xxfc_sources src/regex/xx_regex_unicode16.c)
    endif()
    # Newer xxfclib I/O implementations keep the buffer dispatchers here.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/io/xx_io_buffer.c")
        list(APPEND _xxfc_sources src/io/xx_io_buffer.c)
    endif()
    # YARA-X-exact PE helpers (RVA/checksum/rich/import/export semantics)
    # backing the pe module; added in the fmt_pe1 lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/executable/pe/xx_pe_yx.c")
        list(APPEND _xxfc_sources src/formats/executable/pe/xx_pe_yx.c)
    endif()
    # YARA-X-exact Authenticode signature extraction (fmt_pe2 lane).
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/executable/pe/xx_pe_yx_authenticode.c")
        list(APPEND _xxfc_sources src/formats/executable/pe/xx_pe_yx_authenticode.c)
    endif()
    # YARA-X-exact ELF helpers (entry-point file offset, PT_DYNAMIC walking,
    # import_md5/telfhash) backing the elf module; added in the fmt_elfetc
    # lane. The lossy UTF-8 / Unicode 17 lowercase helpers live in strings.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/executable/elf/xx_elf_yx.c")
        list(APPEND _xxfc_sources src/formats/executable/elf/xx_elf_yx.c)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/strings/xx_string_casefold.c")
        list(APPEND _xxfc_sources src/strings/xx_string_casefold.c)
    endif()
    # YARA-X-exact icontains/istartswith/iendswith/iequals, bstr/Rust
    # uppercase with the case properties, the unicode-width display widths
    # of diagnostics and Rust's Debug escaping of configuration values;
    # added in the fmt_strings lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/strings/xx_string_casecmp.c")
        list(APPEND _xxfc_sources src/strings/xx_string_casecmp.c)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/strings/xx_string_uppercase.c")
        list(APPEND _xxfc_sources src/strings/xx_string_uppercase.c)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/strings/xx_string_width.c")
        list(APPEND _xxfc_sources src/strings/xx_string_width.c)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/strings/xx_string_escape_debug.c")
        list(APPEND _xxfc_sources src/strings/xx_string_escape_debug.c)
    endif()
    # YARA-X-exact ZIP helpers (EOCD/ZIP64 recovery, lossy-UTF8 entry paths)
    # backing the zip module; added in the fmt_elfetc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/archive/zip/xx_zip_yx.c")
        list(APPEND _xxfc_sources src/formats/archive/zip/xx_zip_yx.c)
    endif()
    # YARA-X-exact LNK helpers (ShellLinkHeader, IDList, LinkInfo, TrackerData,
    # overlay) backing the lnk module; added in the fmt_elfetc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/other/windows_shell_link/xx_lnk_yx.c")
        list(APPEND _xxfc_sources src/formats/other/windows_shell_link/xx_lnk_yx.c)
    endif()
    # YARA-X-exact DEX helpers (header validation, lazy tables, MUTF-8,
    # map_list placeholder, contains_*) backing the dex module.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/executable/dex/xx_dex_yx.c")
        list(APPEND _xxfc_sources src/formats/executable/dex/xx_dex_yx.c)
    endif()
    # YARA-X-exact .NET helpers (PE/CLR metadata root, 15,000-row table cap,
    # 256-stream cap, raw UTF-16LE #US strings, typelib extraction, ECMA-335
    # signature formatting) backing the dotnet module; added in the
    # fmt_dotnet lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/executable/dotnet/xx_dotnet_yx.c")
        list(APPEND _xxfc_sources
            src/formats/executable/dotnet/xx_dotnet_yx.c
            src/formats/executable/dotnet/xx_dotnet_yx_method.c)
    endif()
    # YARA-X-exact CRX helpers (Cr24 framing, protobuf proofs, manifest and
    # locale extraction, signature verification, permhash) backing the crx
    # module; added in the fmt_elfetc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/installer/crx/xx_crx_yx.c")
        list(APPEND _xxfc_sources src/formats/installer/crx/xx_crx_yx.c)
    endif()
    # TOML 1.0 document parser whose diagnostics match the Rust toml 0.8
    # crate, as the YARA-X CLI's configuration reader expects; added in the
    # fmt_misc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/toml/xx_toml.c")
        list(APPEND _xxfc_sources src/toml/xx_toml.c)
    endif()
    # YARA-X-exact vt network helpers (Rust std IpAddr + ipnet 2.12.2 CIDR
    # parsing, the psl 2.1.243 public-suffix lookup and the vt module's
    # domain-permutation engines) backing the vt module; added in the
    # fmt_misc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/net/xx_domain_yx.c")
        list(APPEND _xxfc_sources src/net/xx_domain_yx.c)
    endif()
    # YARA-X-exact Cuckoo report reader (serde_json-compatible decoding and
    # diagnostics) backing the cuckoo module; added in the fmt_misc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/other/cuckoo/xx_cuckoo_yx.c")
        list(APPEND _xxfc_sources src/formats/other/cuckoo/xx_cuckoo_yx.c)
    endif()
    # YARA-X-exact Mach-O helpers (fat flattening, load commands, entry point,
    # uuid/source/build version, code-signature extras, symhash) backing the
    # macho module; added in the fmt_elfetc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/executable/macho/xx_macho_yx.c")
        list(APPEND _xxfc_sources src/formats/executable/macho/xx_macho_yx.c)
    endif()
    # YARA-X-exact OLECF / MSI / VBA helpers (compound-file reader with
    # IndexMap directory order, MsiHasher input, MS-OVBA project parsing and
    # decompression) backing the olecf, msi and vba modules; added in the
    # fmt_elfetc lane.
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/document/cfbf/xx_olecf_yx.c")
        list(APPEND _xxfc_sources src/formats/document/cfbf/xx_olecf_yx.c)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/installer/msi/xx_msi_yx.c")
        list(APPEND _xxfc_sources src/formats/installer/msi/xx_msi_yx.c)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/src/formats/document/vba/xx_vba_yx.c")
        list(APPEND _xxfc_sources src/formats/document/vba/xx_vba_yx.c)
    endif()
    # Styled console output (dump colors) for the command-line tool.
    list(APPEND _xxfc_sources
        src/terminal/xx_terminal.c
        src/terminal/xx_terminal_color.c)
    # Exact byte statistics kernels used by the math and hash modules.
    list(APPEND _xxfc_sources
        src/algo/bytestats/xx_bytestats.c
        src/algo/bytestats/platforms/xx_bytestats_sse2.c
        src/algo/bytestats/platforms/xx_bytestats_avx2.c)
    # YARA-X-form entropy (-p*log2(p)) used by the math module.
    list(APPEND _xxfc_sources
        src/algo/entropy/xx_entropy_log2.c)
    # Buffer base64 coding used by the base64 module, the JSON dump and CRX.
    list(APPEND _xxfc_sources
        src/algo/base64/xx_base64.c)
    # TLSH (ELF telfhash profile) and Adler-32 (DEX checksum), plus the
    # buffer/PE-maker homes of the YARA-X-flavoured PE checksum.
    list(APPEND _xxfc_sources
        src/algo/tlsh/xx_tlsh.c
        src/algo/adler32/xx_adler32.c
        src/algo/adler32/platforms/xx_adler32_sse2.c
        src/algo/adler32/platforms/xx_adler32_avx2.c
        src/algo/adler32/platforms/xx_adler32_neon.c
        src/algo/adler32/platforms/xx_adler32_arm_dotprod.c
        src/buf/xx_buf.c
        src/formats/executable/pe/xx_pe_make.c)
    if(MSVC)
        set_source_files_properties(
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/bytestats/platforms/xx_bytestats_avx2.c"
            PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    endif()
    # Masked multi-byte probe search for hex patterns without a literal atom.
    list(APPEND _xxfc_sources
        src/algo/maskscan/xx_maskscan.c
        src/algo/maskscan/platforms/xx_maskscan_sse2.c
        src/algo/maskscan/platforms/xx_maskscan_avx2.c)
    if(MSVC)
        set_source_files_properties(
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/maskscan/platforms/xx_maskscan_avx2.c"
            PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    endif()
    # First byte of a buffer in a byte set: the regexp atom index jumps
    # between possible atom starts with it.
    list(APPEND _xxfc_sources
        src/algo/byteset/xx_byteset.c
        src/algo/byteset/platforms/xx_byteset_sse2.c
        src/algo/byteset/platforms/xx_byteset_avx2.c)
    if(MSVC)
        set_source_files_properties(
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/byteset/platforms/xx_byteset_avx2.c"
            PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    endif()
    if(WIN32)
        list(APPEND _xxfc_sources
            src/io/platforms/xx_io_windows.c
            src/global/platforms/xx_global_windows.c
            src/memory/platforms/xx_memory_windows.c
            src/rt/platforms/xx_rt_windows.c
            src/strings/platforms/xx_string_windows.c
            src/terminal/platforms/xx_terminal_windows.c
            src/threads/platforms/xx_threads_windows.c)
    else()
        list(APPEND _xxfc_sources
            src/io/platforms/xx_io_posix.c
            src/global/platforms/xx_global_posix.c
            src/memory/platforms/xx_memory_posix.c
            src/rt/platforms/xx_rt_posix.c
            src/strings/platforms/xx_string_posix.c
            src/terminal/platforms/xx_terminal_posix.c
            src/threads/platforms/xx_threads_posix.c)
    endif()
    # The portable cores of the CRT-free runtime (UCRT-identical formatting,
    # conversions, qsort, ctype, math, time); the Windows standard-name layer
    # is the separate xxyara_crt library below.
    if(XXYARA_NO_CRT)
        list(APPEND _xxfc_sources
            src/crt/xx_crt_fmt.c
            src/crt/xx_crt_scan.c
            src/crt/xx_crt_strtod.c
            src/crt/xx_crt_conv.c
            src/crt/xx_crt_qsort.c
            src/crt/xx_crt_ctype.c
            src/crt/xx_crt_string.c
            src/crt/xx_crt_math.c
            src/crt/xx_ms_log2.c
            src/crt/xx_crt_time.c)
    endif()
    list(TRANSFORM _xxfc_sources PREPEND "${XXYARA_XXFCLIB_SOURCE_DIR}/")
    # Reuse the codepage registry's source closure and table options. The
    # WHATWG buffer decoder above is required by the CLI on every platform.
    include("${XXYARA_XXFCLIB_SOURCE_DIR}/cmake/xxfclib_codepages.cmake")
    foreach(_xxfc_codepage_source IN LISTS XXFC_CODEPAGE_SOURCES)
        get_filename_component(_xxfc_codepage_source "${_xxfc_codepage_source}" ABSOLUTE)
        list(APPEND _xxfc_sources "${_xxfc_codepage_source}")
    endforeach()
    list(REMOVE_DUPLICATES _xxfc_sources)
    foreach(_xxfc_source IN LISTS _xxfc_sources)
        if(NOT EXISTS "${_xxfc_source}")
            message(FATAL_ERROR "xxfclib source file is missing: ${_xxfc_source}")
        endif()
    endforeach()

    add_library(xxyara_xxfclib STATIC ${_xxfc_sources})
    add_library(xxfclib::xxfclib ALIAS xxyara_xxfclib)
    target_include_directories(xxyara_xxfclib PUBLIC
        "${XXYARA_XXFCLIB_SOURCE_DIR}/include")
    target_compile_features(xxyara_xxfclib PUBLIC c_std_11)
    target_compile_definitions(xxyara_xxfclib PUBLIC XXFC_STATIC)
    set_target_properties(xxyara_xxfclib PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON)
    if(MSVC)
        set_source_files_properties(
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/data/platforms/xx_data_avx2.c"
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/memory/platforms/xx_memory_avx2.c"
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/crc/platforms/xx_crc64_avx2.c"
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/deflate/platforms/xx_deflate_avx2.c"
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/adler32/platforms/xx_adler32_avx2.c"
            PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    else()
        target_compile_options(xxyara_xxfclib PRIVATE -ffunction-sections -fdata-sections)
        if(NOT WIN32)
            find_package(Threads REQUIRED)
            target_link_libraries(xxyara_xxfclib PUBLIC Threads::Threads m ${CMAKE_DL_LIBS})
        endif()
    endif()
    if(MSVC AND CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^(X86|x86|x64|AMD64)$")
        set_source_files_properties(
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/literal/xx_literal_avx2.c"
            PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    endif()
endif()

add_library(xxyara_common OBJECT
    src/warning_suppression.c
    src/serialization.c
    src/parser.c
    src/syntax_check.c
    src/match.c
    src/native_regex.c
    src/regex_vm.c
    src/base64.c
    src/module_hash.c
    src/module_crx.c
    src/module_dex.c
    src/module_elf.c
    src/module_lnk.c
    src/module_macho.c
    src/module_pe.c
    src/module_zip.c
    src/module_string.c
    src/module_vt.c
    src/module_output.c
    src/condition.c)
if(XXYARA_ENABLE_PROFILING)
    target_compile_definitions(xxyara_common PUBLIC XXYARA_ENABLE_PROFILING=1)
endif()
if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(xxyara_common PUBLIC Threads::Threads)
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/module_dotnet.c")
    target_sources(xxyara_common PRIVATE src/module_dotnet.c)
endif()
if(XXYARA_ENABLE_MAGIC)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/module_magic.c")
        message(FATAL_ERROR "The optional magic module source is missing")
    endif()
    target_sources(xxyara_common PRIVATE src/module_magic.c)
    target_compile_definitions(xxyara_common PUBLIC XXYARA_ENABLE_MAGIC=1)
    find_path(XXYARA_MAGIC_INCLUDE_DIR magic.h)
    find_library(XXYARA_MAGIC_LIBRARY NAMES magic)
    if(NOT XXYARA_MAGIC_INCLUDE_DIR OR NOT XXYARA_MAGIC_LIBRARY)
        message(FATAL_ERROR "libmagic headers and library are required for the magic module")
    endif()
    target_include_directories(xxyara_common PRIVATE "${XXYARA_MAGIC_INCLUDE_DIR}")
    target_link_libraries(xxyara_common PRIVATE "${XXYARA_MAGIC_LIBRARY}")
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/module_cuckoo.c")
    target_sources(xxyara_common PRIVATE src/module_cuckoo.c)
endif()
if(XXYARA_ENABLE_OLECF OR XXYARA_ENABLE_MSI)
    # The msi module reads streams with the OLECF parser; it does not make
    # the olecf module itself importable.
    target_sources(xxyara_common PRIVATE src/module_olecf.c)
endif()
if(XXYARA_ENABLE_OLECF)
    target_compile_definitions(xxyara_common PUBLIC XXYARA_ENABLE_OLECF=1)
endif()
if(XXYARA_ENABLE_MSI)
    target_sources(xxyara_common PRIVATE src/module_msi.c)
    target_compile_definitions(xxyara_common PUBLIC XXYARA_ENABLE_MSI=1)
endif()
if(XXYARA_ENABLE_VBA)
    target_sources(xxyara_common PRIVATE src/module_vba.c)
    target_compile_definitions(xxyara_common PUBLIC XXYARA_ENABLE_VBA=1)
endif()
target_include_directories(xxyara_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_features(xxyara_common PUBLIC c_std_11)
target_link_libraries(xxyara_common PUBLIC xxfclib::xxfclib)
target_compile_definitions(xxyara_common PUBLIC
    XXYARA_NATIVE_REGEX=1 XXYARA_HAVE_PCRE2=1)
set_target_properties(xxyara_common PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

# Compile the shared implementation once. Only the API/compiler driver controls
# module registration, so the unit-test library can enable test schemas without
# adding them to the release library or CLI.
add_library(xxyara STATIC src/xxyara.c)
add_library(xxyara::xxyara ALIAS xxyara)
target_link_libraries(xxyara PUBLIC xxyara_common)
set_target_properties(xxyara PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON OUTPUT_NAME xxyara)
if(XXYARA_ENABLE_TEST_PROTO)
    target_compile_definitions(xxyara PUBLIC XXYARA_ENABLE_TEST_PROTO=1)
endif()

# The export list of the shared library must name exactly the functions the
# public headers declare, so a new C API function cannot be left unexported.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/yara_x.h" _xxyara_api_header)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/xxyara_ext.h" _xxyara_ext_header)
string(REGEX MATCHALL "\n[a-z][^\n;(]*[ *](yrx_[a-z0-9_]+|xxyara_[a-z0-9_]+)\\("
    _xxyara_api_decls "${_xxyara_api_header}\n${_xxyara_ext_header}")
set(_xxyara_api_names "")
foreach(_xxyara_decl IN LISTS _xxyara_api_decls)
    string(REGEX MATCH "(yrx_[a-z0-9_]+|xxyara_[a-z0-9_]+)\\($" _xxyara_name "${_xxyara_decl}")
    string(REGEX REPLACE "\\($" "" _xxyara_name "${_xxyara_name}")
    list(APPEND _xxyara_api_names "${_xxyara_name}")
endforeach()
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/xxyara.def" _xxyara_def_names
    REGEX "^(yrx|xxyara)_[a-z0-9_]+$")
list(SORT _xxyara_api_names)
list(REMOVE_DUPLICATES _xxyara_api_names)
list(SORT _xxyara_def_names)
if(NOT _xxyara_api_names STREQUAL _xxyara_def_names)
    message(FATAL_ERROR "src/xxyara.def does not match the functions declared in "
        "include/yara_x.h and include/xxyara_ext.h.\nHeaders: ${_xxyara_api_names}\n"
        "xxyara.def: ${_xxyara_def_names}")
endif()

# Windows version resources (CompanyName, LegalCopyright, ProductName,
# FileDescription and PROJECT_VERSION) for xxyara.dll, yr.exe and xxyara.exe.
# They change no program output.
set(_xxyara_version_rc OFF)
if(WIN32 AND (MSVC OR MINGW))
    enable_language(RC)
    set(_xxyara_version_rc ON)
endif()
function(xxyara_add_version_resource target file_name description file_type)
    if(NOT _xxyara_version_rc)
        return()
    endif()
    set(XXYARA_RC_ORIGINAL_FILENAME "${file_name}")
    get_filename_component(XXYARA_RC_INTERNAL_NAME "${file_name}" NAME_WE)
    set(XXYARA_RC_DESCRIPTION "${description}")
    set(XXYARA_RC_FILETYPE "${file_type}")
    set(_rc "${CMAKE_CURRENT_BINARY_DIR}/version_resources/${target}.rc")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/xxyara_version.rc.in" "${_rc}" @ONLY)
    target_sources(${target} PRIVATE "${_rc}")
endfunction()
# The YARA-X release the command line reproduces (YX_CLI_VERSION).
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/cli_help_data.h" _xxyara_cli_version_line
    REGEX "^#define YX_CLI_VERSION \"[0-9.]+\"$")
string(REGEX REPLACE "^#define YX_CLI_VERSION \"([0-9.]+)\"$" "\\1"
    YX_CLI_VERSION_FOR_RC "${_xxyara_cli_version_line}")

# The same library as a DLL / shared object (xxyara.dll, libxxyara.so). It
# exports the YARA-X C API with the same names as YARA-X's yara_x_capi.dll,
# plus the xxyara extensions, and contains xxfclib, so it has no other
# dependency. MSVC names its import library xxyara.dll.lib so that it does not
# collide with the static xxyara.lib (the same scheme as yara_x_capi.dll.lib).
if(XXYARA_BUILD_SHARED)
    add_library(xxyara_shared SHARED src/xxyara.c)
    add_library(xxyara::shared ALIAS xxyara_shared)
    target_link_libraries(xxyara_shared PRIVATE xxyara_common)
    target_include_directories(xxyara_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
    set_target_properties(xxyara_shared PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON OUTPUT_NAME xxyara)
    if(XXYARA_ENABLE_TEST_PROTO)
        target_compile_definitions(xxyara_shared PRIVATE XXYARA_ENABLE_TEST_PROTO=1)
    endif()
    xxyara_add_version_resource(xxyara_shared xxyara.dll
        "xxyara library (YARA-X ${YX_CLI_VERSION_FOR_RC} C API), based on YARA-X by Victor M. Alvarez" VFT_DLL)
    if(WIN32)
        target_sources(xxyara_shared PRIVATE src/xxyara.def)
        set_target_properties(xxyara_shared PROPERTIES PREFIX "")
        if(MSVC)
            set_target_properties(xxyara_shared PROPERTIES IMPORT_SUFFIX ".dll.lib")
        endif()
    elseif(NOT APPLE)
        target_link_options(xxyara_shared PRIVATE
            "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/xxyara.map")
    endif()
endif()

if(XXYARA_BUILD_CLI)
    add_executable(xxyara_cli src/cli.c src/cli_regex.c src/cli_dump.c src/cli_help_data.c
        src/completion_data.c)
    set_target_properties(xxyara_cli PROPERTIES OUTPUT_NAME yr)
    target_link_libraries(xxyara_cli PRIVATE xxyara::xxyara)
    xxyara_add_version_resource(xxyara_cli yr.exe
        "yr, the YARA-X ${YX_CLI_VERSION_FOR_RC} command line (xxyara), based on YARA-X by Victor M. Alvarez" VFT_APP)
endif()

# xxyara: the console application. The same sources as yr, so the same
# commands, options and output; XXYARA_CLI_BRANDED (src/cli_branding.h) gives it
# its own banner, version line and program name. yr keeps printing exactly
# what YARA-X's yr prints.
if(XXYARA_BUILD_CONSOLE)
    add_executable(xxyara_console src/cli.c src/cli_regex.c src/cli_dump.c src/cli_help_data.c
        src/completion_data.c)
    # xxyara.exe sits next to xxyara.dll and the static xxyara.lib: keep its
    # PDB, incremental-link database and any import library from taking their
    # names (both links would otherwise use xxyara.pdb / xxyara.ilk).
    set_target_properties(xxyara_console PROPERTIES OUTPUT_NAME xxyara
        PDB_NAME xxyara_console IMPORT_SUFFIX ".exe.lib")
    if(MSVC)
        target_link_options(xxyara_console PRIVATE
            "/ILK:${CMAKE_CURRENT_BINARY_DIR}/xxyara_console.dir/$<CONFIG>/xxyara_console.ilk")
    endif()
    target_compile_definitions(xxyara_console PRIVATE XXYARA_CLI_BRANDED=1
        XXYARA_CLI_VERSION="${PROJECT_VERSION}")
    target_link_libraries(xxyara_console PRIVATE xxyara::xxyara)
    xxyara_add_version_resource(xxyara_console xxyara.exe
        "xxyara console application (YARA-X ${YX_CLI_VERSION_FOR_RC} compatible), based on YARA-X by Victor M. Alvarez" VFT_APP)
endif()

if(XXYARA_BUILD_TESTS)
    include(CTest)
endif()
if(XXYARA_BUILD_TESTS AND BUILD_TESTING)
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/literal/test_literal.c")
        add_executable(test_literal
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/literal/test_literal.c")
        target_link_libraries(test_literal PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_literal COMMAND test_literal)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/literal_nocase/test_literal_nocase.c")
        add_executable(test_literal_nocase
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/literal_nocase/test_literal_nocase.c")
        target_link_libraries(test_literal_nocase PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_literal_nocase COMMAND test_literal_nocase)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_atom_candidates.c")
        add_executable(test_atom_candidates tests/test_atom_candidates.c)
        target_include_directories(test_atom_candidates PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_atom_candidates PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_atom_candidates COMMAND test_atom_candidates)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/pki/pki_followup_test.c")
        add_executable(test_pki_followup
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/pki/pki_followup_test.c")
        target_link_libraries(test_pki_followup PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_pki_followup COMMAND test_pki_followup)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/bytestats/bytestats_test.c")
        add_executable(test_bytestats
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/bytestats/bytestats_test.c")
        target_link_libraries(test_bytestats PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_bytestats COMMAND test_bytestats)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/maskscan/maskscan_test.c")
        add_executable(test_maskscan
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/maskscan/maskscan_test.c")
        target_link_libraries(test_maskscan PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_maskscan COMMAND test_maskscan)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/byteset/byteset_test.c")
        add_executable(test_byteset
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/byteset/byteset_test.c")
        # The test forces strategies through the internal platform header.
        target_include_directories(test_byteset PRIVATE
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/algo/byteset")
        target_link_libraries(test_byteset PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_byteset COMMAND test_byteset)
        set_tests_properties(xxyara_byteset PROPERTIES TIMEOUT 600)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/formats/pe/test_pe_yx.c")
        add_executable(test_pe_yx
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/formats/pe/test_pe_yx.c")
        target_link_libraries(test_pe_yx PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_pe_yx COMMAND test_pe_yx)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/bytestats/bytestats_stats_test.c")
        add_executable(test_bytestats_stats
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/bytestats/bytestats_stats_test.c")
        target_link_libraries(test_bytestats_stats PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_bytestats_stats COMMAND test_bytestats_stats)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/entropy/entropy_log2_test.c")
        add_executable(test_entropy_log2
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/entropy/entropy_log2_test.c")
        target_link_libraries(test_entropy_log2 PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_entropy_log2 COMMAND test_entropy_log2)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/base64/base64_test.c")
        add_executable(test_base64_primitive
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/base64/base64_test.c")
        target_link_libraries(test_base64_primitive PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_base64_primitive COMMAND test_base64_primitive)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/tlsh/tlsh_test.c")
        add_executable(test_tlsh
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/tlsh/tlsh_test.c")
        target_link_libraries(test_tlsh PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_tlsh COMMAND test_tlsh)
    endif()
    if(EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/adler32/adler32_test.c")
        add_executable(test_adler32
            "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/algo/adler32/adler32_test.c")
        target_link_libraries(test_adler32 PRIVATE xxfclib::xxfclib)
        add_test(NAME xxyara_adler32 COMMAND test_adler32)
    endif()
    # xxfclib's C runtime cores against Microsoft's static UCRT: this test
    # links the real runtime (/Zl removed the default library records, so the
    # /MT libraries are named) and compares the two on random and edge cases.
    if(XXYARA_NO_CRT AND EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/crt_ucrt_diff.c")
        add_executable(test_crt_ucrt_diff "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/crt_ucrt_diff.c"
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/crt/platforms/xx_crt_args_windows.c")
        target_link_libraries(test_crt_ucrt_diff PRIVATE xxfclib::xxfclib
            $<IF:$<CONFIG:Debug>,libcmtd,libcmt> $<IF:$<CONFIG:Debug>,libvcruntimed,libvcruntime>
            $<IF:$<CONFIG:Debug>,libucrtd,libucrt>)
        add_test(NAME xxyara_crt_ucrt_diff COMMAND test_crt_ucrt_diff --scale 1 --log2-exhaustive 512)
        set_tests_properties(xxyara_crt_ucrt_diff PROPERTIES TIMEOUT 1200)
    endif()
    # xx_ms_log2 (the log2 of the CRT-free layer) against the log2 of
    # Microsoft's static UCRT, bit for bit: specials, powers of two,
    # subnormals, random doubles, c/n for every n <= 4096 and 200,000 entropy
    # sums, with the runtime's FMA3 paths on and off. x64 only: xx_ms_log2
    # reproduces the x64 UCRT on every architecture and the 32-bit UCRT has
    # another log2.
    if(XXYARA_NO_CRT AND CMAKE_SIZEOF_VOID_P EQUAL 8
       AND EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/ms_log2_ucrt_test.c")
        add_executable(test_ms_log2_ucrt "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/ms_log2_ucrt_test.c")
        target_link_libraries(test_ms_log2_ucrt PRIVATE xxfclib::xxfclib
            $<IF:$<CONFIG:Debug>,libcmtd,libcmt> $<IF:$<CONFIG:Debug>,libvcruntimed,libvcruntime>
            $<IF:$<CONFIG:Debug>,libucrtd,libucrt>)
        add_test(NAME xxyara_ms_log2_ucrt COMMAND test_ms_log2_ucrt)
        set_tests_properties(xxyara_ms_log2_ucrt PROPERTIES TIMEOUT 1200)
    endif()
    # The parts of the runtime that exist only as standard names (streams,
    # environment, paths, stat, errno): one probe source built against
    # Microsoft's runtime (test_crt_probe_ucrt) and against xxfclib's
    # (test_crt_probe); both must print the same.
    if(XXYARA_NO_CRT AND EXISTS "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/crt_platform_probe.c")
        add_executable(test_crt_probe "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/crt_platform_probe.c")
        add_executable(test_crt_probe_ucrt "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/crt_platform_probe.c")
        target_link_libraries(test_crt_probe PRIVATE xxfclib::xxfclib)
        target_link_libraries(test_crt_probe_ucrt PRIVATE
            $<IF:$<CONFIG:Debug>,libcmtd,libcmt> $<IF:$<CONFIG:Debug>,libvcruntimed,libvcruntime>
            $<IF:$<CONFIG:Debug>,libucrtd,libucrt>)
        add_test(NAME xxyara_crt_platform_probe COMMAND "${CMAKE_COMMAND}"
            -DREFERENCE=$<TARGET_FILE:test_crt_probe_ucrt> -DCANDIDATE=$<TARGET_FILE:test_crt_probe>
            -DWORK=${CMAKE_CURRENT_BINARY_DIR}/crt-platform-probe
            -P "${XXYARA_XXFCLIB_SOURCE_DIR}/tests/crt/compare_probe_outputs.cmake")
        set_tests_properties(xxyara_crt_platform_probe PROPERTIES TIMEOUT 1200)
        # A search that costs a restarting strstr about 64 billion comparisons.
        add_test(NAME xxyara_crt_strstr_adversarial COMMAND test_crt_probe strstr-adversarial)
        set_tests_properties(xxyara_crt_strstr_adversarial PROPERTIES TIMEOUT 60
            PASS_REGULAR_EXPRESSION "match at the end: ok" FAIL_REGULAR_EXPRESSION "WRONG;FOUND")
        # Loading and unloading the CRT-free DLL leaves no handles behind.
        if(TARGET xxyara_shared)
            add_test(NAME xxyara_crt_dll_cycle COMMAND test_crt_probe dll-cycle $<TARGET_FILE:xxyara_shared>)
            set_tests_properties(xxyara_crt_dll_cycle PROPERTIES TIMEOUT 300)
        endif()
    endif()
    if(XXYARA_ENABLE_TEST_PROTO)
        set(_xxyara_test_modules xxyara::xxyara)
    else()
        add_library(xxyara_test_modules STATIC src/xxyara.c)
        target_link_libraries(xxyara_test_modules PUBLIC xxyara_common)
        target_compile_definitions(xxyara_test_modules PUBLIC XXYARA_ENABLE_TEST_PROTO=1)
        set_target_properties(xxyara_test_modules PROPERTIES
            C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
            POSITION_INDEPENDENT_CODE ON)
        set(_xxyara_test_modules xxyara_test_modules)
    endif()
    add_executable(test_release_modules tests/test_release_modules.c)
    target_link_libraries(test_release_modules PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_release_modules COMMAND test_release_modules)

    add_executable(test_native_regex tests/test_native_regex.c)
    target_link_libraries(test_native_regex PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_native_regex COMMAND test_native_regex)
    add_executable(test_codepage_whatwg tests/test_codepage_whatwg.c)
    target_link_libraries(test_codepage_whatwg PRIVATE xxfclib::xxfclib)
    add_test(NAME xxyara_codepage_whatwg COMMAND test_codepage_whatwg)
    if(WIN32)
        add_executable(test_crx_crypto_windows tests/test_crx_crypto_windows.c)
        target_include_directories(test_crx_crypto_windows PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_crx_crypto_windows PRIVATE xxyara::xxyara)
        target_link_libraries(test_crx_crypto_windows PRIVATE crypt32 bcrypt)
        add_test(NAME xxyara_native_crx_crypto COMMAND test_crx_crypto_windows)
    endif()
    add_executable(test_toml tests/test_toml.c)
    target_include_directories(test_toml PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_features(test_toml PRIVATE c_std_11)
    target_link_libraries(test_toml PRIVATE xxfclib::xxfclib)
    add_test(NAME xxyara_toml COMMAND test_toml)

    add_executable(test_cli_regex tests/test_cli_regex.c src/cli_regex.c)
    target_include_directories(test_cli_regex PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test_cli_regex PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_cli_regex COMMAND test_cli_regex)
    add_executable(test_terminal_ansi tests/test_terminal_ansi.c)
    target_link_libraries(test_terminal_ansi PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_terminal_ansi COMMAND test_terminal_ansi)

    add_executable(test_xxyara tests/test_xxyara.c)
    target_link_libraries(test_xxyara PRIVATE xxyara::xxyara)
    add_test(NAME xxyara COMMAND test_xxyara)

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_api.c")
        add_executable(test_api tests/test_api.c)
        target_link_libraries(test_api PRIVATE ${_xxyara_test_modules})
        add_test(NAME xxyara_api COMMAND test_api)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_load_scale.c")
        add_executable(test_load_scale tests/test_load_scale.c)
        target_link_libraries(test_load_scale PRIVATE ${_xxyara_test_modules})
        add_test(NAME xxyara_load_scale COMMAND test_load_scale)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_tail_filter.c")
        add_executable(test_tail_filter tests/test_tail_filter.c)
        target_link_libraries(test_tail_filter PRIVATE ${_xxyara_test_modules})
        add_test(NAME xxyara_tail_filter COMMAND test_tail_filter)
    endif()
    # PikeVM atom windows: scans with and without them report the same matches.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_rx_windows.c")
        add_executable(test_rx_windows tests/test_rx_windows.c)
        target_include_directories(test_rx_windows PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_rx_windows PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_rx_windows COMMAND test_rx_windows)
    endif()
    # Atom index search: jumping between possible atom starts reports the
    # same matches as visiting every position, also in the scanner's
    # full-search fallback after 1,000,000 candidates.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_rx_index_skip.c")
        add_executable(test_rx_index_skip tests/test_rx_index_skip.c)
        target_include_directories(test_rx_index_skip PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_rx_index_skip PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_rx_index_skip COMMAND test_rx_index_skip)
        set_tests_properties(xxyara_rx_index_skip PROPERTIES TIMEOUT 300)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_serialization.c")
        add_executable(test_serialization tests/test_serialization.c)
        target_link_libraries(test_serialization PRIVATE ${_xxyara_test_modules})
        add_test(NAME xxyara_serialization COMMAND test_serialization)
        add_test(NAME xxyara_serialization_atom_ac
            COMMAND test_serialization --atom-ac-layout)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_hex.c")
        add_executable(test_hex tests/test_hex.c)
        target_link_libraries(test_hex PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_hex COMMAND test_hex)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_base64.c")
        add_executable(test_base64 tests/test_base64.c)
        target_link_libraries(test_base64 PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_base64 COMMAND test_base64)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_unicode_casefold.c")
        add_executable(test_unicode_casefold tests/test_unicode_casefold.c)
        target_include_directories(test_unicode_casefold PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_unicode_casefold PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_unicode_casefold COMMAND test_unicode_casefold)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_hash.c")
        add_executable(test_module_hash tests/test_module_hash.c)
        target_include_directories(test_module_hash PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_hash PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_hash COMMAND test_module_hash)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_pe.c")
        add_executable(test_module_pe tests/test_module_pe.c)
        target_include_directories(test_module_pe PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_pe PRIVATE xxyara::xxyara)
        if(WIN32)
            target_link_libraries(test_module_pe PRIVATE crypt32 bcrypt)
        endif()
        add_test(NAME xxyara_module_pe COMMAND test_module_pe)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_dotnet.c")
        add_executable(test_module_dotnet tests/test_module_dotnet.c)
        target_include_directories(test_module_dotnet PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_dotnet PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_dotnet COMMAND test_module_dotnet)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_dotnet_method.c")
        add_executable(test_module_dotnet_method tests/test_module_dotnet_method.c)
        target_include_directories(test_module_dotnet_method PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_dotnet_method PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_dotnet_method COMMAND test_module_dotnet_method)
    endif()
    if(XXYARA_ENABLE_MAGIC AND
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_magic.c")
        add_executable(test_module_magic tests/test_module_magic.c)
        target_include_directories(test_module_magic PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_magic PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_magic COMMAND test_module_magic)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_cuckoo.c")
        add_executable(test_module_cuckoo tests/test_module_cuckoo.c)
        target_include_directories(test_module_cuckoo PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_cuckoo PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_cuckoo COMMAND test_module_cuckoo)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_elf.c")
        add_executable(test_module_elf tests/test_module_elf.c)
        target_include_directories(test_module_elf PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_elf PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_elf COMMAND test_module_elf)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_dex.c")
        add_executable(test_module_dex tests/test_module_dex.c)
        target_include_directories(test_module_dex PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_dex PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_dex COMMAND test_module_dex)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_zip.c")
        add_executable(test_module_zip tests/test_module_zip.c)
        target_include_directories(test_module_zip PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_zip PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_zip COMMAND test_module_zip)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_macho.c")
        add_executable(test_module_macho tests/test_module_macho.c)
        target_include_directories(test_module_macho PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_macho PRIVATE xxyara::xxyara)
        if(WIN32)
            target_link_libraries(test_module_macho PRIVATE crypt32 bcrypt ncrypt)
        endif()
        if(XXYARA_BUILD_CLI AND UNIX)
            add_dependencies(test_module_macho xxyara_cli)
            target_compile_definitions(test_module_macho PRIVATE
                XXYARA_TEST_YR_PATH="$<TARGET_FILE:xxyara_cli>")
        endif()
        add_test(NAME xxyara_module_macho COMMAND test_module_macho)
    endif()
    if(XXYARA_ENABLE_OLECF AND
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_olecf.c")
        add_executable(test_module_olecf tests/test_module_olecf.c)
        target_include_directories(test_module_olecf PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_olecf PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_olecf COMMAND test_module_olecf)
    endif()
    if(XXYARA_ENABLE_MSI AND
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_msi.c")
        add_executable(test_module_msi tests/test_module_msi.c)
        target_include_directories(test_module_msi PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_msi PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_msi COMMAND test_module_msi)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_vt.c")
        add_executable(test_module_vt tests/test_module_vt.c)
        target_include_directories(test_module_vt PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_vt PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_vt COMMAND test_module_vt)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ignore_module.c")
        add_executable(test_ignore_module tests/test_ignore_module.c)
        target_include_directories(test_ignore_module PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_ignore_module PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_ignore_module COMMAND test_ignore_module)
    endif()
    if(XXYARA_ENABLE_VBA AND
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_vba.c")
        add_executable(test_module_vba tests/test_module_vba.c)
        target_include_directories(test_module_vba PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_vba PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_vba COMMAND test_module_vba)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_lnk.c")
        add_executable(test_module_lnk tests/test_module_lnk.c)
        target_include_directories(test_module_lnk PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_lnk PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_lnk COMMAND test_module_lnk)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_crx.c")
        add_executable(test_module_crx tests/test_module_crx.c)
        target_include_directories(test_module_crx PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_crx PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_crx COMMAND test_module_crx)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_module_string.c")
        add_executable(test_module_string tests/test_module_string.c)
        target_include_directories(test_module_string PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test_module_string PRIVATE xxyara::xxyara)
        add_test(NAME xxyara_module_string COMMAND test_module_string)
    endif()
    add_executable(test_scan_candidates tests/test_scan_candidates.c)
    target_include_directories(test_scan_candidates PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test_scan_candidates PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_scan_candidates COMMAND test_scan_candidates)
    add_executable(test_match_limit tests/test_match_limit.c)
    target_link_libraries(test_match_limit PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_match_limit COMMAND test_match_limit)
    add_executable(test_meta tests/test_meta.c)
    target_link_libraries(test_meta PRIVATE xxyara::xxyara)
    add_test(NAME xxyara_meta COMMAND test_meta)
    if(XXYARA_BUILD_CLI)
        if(XXYARA_ENABLE_TEST_PROTO)
            set(_xxyara_unit_cli xxyara_cli)
        else()
            add_executable(xxyara_test_cli src/cli.c src/cli_regex.c
                src/cli_dump.c src/cli_help_data.c src/completion_data.c)
            set_target_properties(xxyara_test_cli PROPERTIES OUTPUT_NAME yr-test-modules)
            target_link_libraries(xxyara_test_cli PRIVATE ${_xxyara_test_modules})
            set(_xxyara_unit_cli xxyara_test_cli)
        endif()
        if(XXYARA_BUILD_CONSOLE)
            add_test(NAME xxyara_console
                COMMAND ${CMAKE_COMMAND}
                    "-DYR=$<TARGET_FILE:xxyara_cli>"
                    "-DXXYARA=$<TARGET_FILE:xxyara_console>"
                    "-DDATA_DIR=${CMAKE_CURRENT_SOURCE_DIR}/examples/data"
                    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/xxyara-console-test"
                    "-DVERSION=${PROJECT_VERSION}"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_xxyara_console.cmake")
        endif()
        add_test(NAME xxyara_dump_escape
            COMMAND ${CMAKE_COMMAND}
                "-DYR=$<TARGET_FILE:xxyara_cli>"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_dump_escape.cmake")
        if(WIN32)
            add_executable(test_cli_fixture_writer tests/test_cli_fixture_writer.c)
            target_compile_features(test_cli_fixture_writer PRIVATE c_std_11)
            set(_cli_fixture_writer "$<TARGET_FILE:test_cli_fixture_writer>")
        endif()
        add_test(NAME xxyara_cli
            COMMAND ${CMAKE_COMMAND}
                "-DYR=$<TARGET_FILE:${_xxyara_unit_cli}>"
                "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-test-data"
                "-DFIXTURE_WRITER=${_cli_fixture_writer}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.cmake")
        add_test(NAME xxyara_pe_dump
            COMMAND ${CMAKE_COMMAND}
                "-DYR=$<TARGET_FILE:xxyara_cli>"
                "-DREFERENCE_YR=${XXYARA_REFERENCE_YR}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_pe_dump.cmake")
        add_test(NAME xxyara_cli_ignore_module
            COMMAND ${CMAKE_COMMAND}
                "-DYR=$<TARGET_FILE:xxyara_cli>"
                "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-ignore-module"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_ignore_module.cmake")
        if(XXYARA_REFERENCE_YR)
            find_package(Python3 COMPONENTS Interpreter QUIET)
            if(Python3_Interpreter_FOUND)
                add_test(NAME xxyara_atom_fastpaths
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_atom_fastpaths.py"
                        --candidate-yr "$<TARGET_FILE:xxyara_cli>"
                        --reference-yr "${XXYARA_REFERENCE_YR}"
                        --work-dir "${CMAKE_CURRENT_BINARY_DIR}/atom-fastpaths")
                set_tests_properties(xxyara_atom_fastpaths PROPERTIES TIMEOUT 300)
                add_test(NAME xxyara_rx_index_skip_reference
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_rx_index_skip_reference.py"
                        --candidate-yr "$<TARGET_FILE:xxyara_cli>"
                        --reference-yr "${XXYARA_REFERENCE_YR}"
                        --work-dir "${CMAKE_CURRENT_BINARY_DIR}/rx-index-skip-reference")
                set_tests_properties(xxyara_rx_index_skip_reference PROPERTIES
                    LABELS "regex;conformance" TIMEOUT 900)
                add_test(NAME xxyara_regex_conformance_fast
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_regex_conformance.py"
                        --run-fast
                        --candidate-yr "$<TARGET_FILE:xxyara_cli>"
                        --reference-yr "${XXYARA_REFERENCE_YR}"
                        --evidence-dir "${CMAKE_CURRENT_BINARY_DIR}/regex-conformance-fast")
                set_tests_properties(xxyara_regex_conformance_fast PROPERTIES
                    LABELS "regex;conformance" TIMEOUT 120)
                add_test(NAME xxyara_regex_rxfix
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_regex_rxfix.py"
                        --reference-yr "${XXYARA_REFERENCE_YR}"
                        --candidate-yr "$<TARGET_FILE:xxyara_cli>"
                        --jobs 4
                        --output-dir "${CMAKE_CURRENT_BINARY_DIR}/regex-rxfix")
                set_tests_properties(xxyara_regex_rxfix PROPERTIES
                    LABELS "regex;conformance" TIMEOUT 600)
                add_test(NAME xxyara_crx_extra_fields
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_crx_extra_fields.py"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--output-dir" "${CMAKE_CURRENT_BINARY_DIR}/crx-extra-fields")
                add_test(NAME xxyara_fmt_followup
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fmt_followup.py"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--output-dir" "${CMAKE_CURRENT_BINARY_DIR}/fmt-followup")
                if(WIN32)
                    add_test(NAME xxyara_cli_dump_colors_windows
                        COMMAND "${Python3_EXECUTABLE}"
                            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_dump_colors_windows.py"
                            "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                            "--reference-yr" "${XXYARA_REFERENCE_YR}"
                            "--output-dir" "${CMAKE_CURRENT_BINARY_DIR}/cli-dump-colors")
                endif()
                add_test(NAME xxyara_encoding_parity
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_encoding_parity.py"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/encoding-parity")
                add_test(NAME xxyara_pf07_evaluator
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/pf07_evaluator_regression.py"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--report" "${CMAKE_CURRENT_BINARY_DIR}/pf07-evaluator-results.json")
                set_tests_properties(xxyara_pf07_evaluator PROPERTIES TIMEOUT 120)
                add_test(NAME xxyara_pf07_range_proofs
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/pf07_evaluator_regression.py"
                        "--manifest" "${CMAKE_CURRENT_SOURCE_DIR}/tests/pf07_range_proof_cases.json"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--report" "${CMAKE_CURRENT_BINARY_DIR}/pf07-range-proof-results.json")
                set_tests_properties(xxyara_pf07_range_proofs PROPERTIES TIMEOUT 120)
                add_test(NAME xxyara_cli_walk_parity
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_walk_parity.py"
                        "--reference" "${XXYARA_REFERENCE_YR}"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/cli-walk-parity")
                add_test(NAME xxyara_cli_check_deps
                    COMMAND ${CMAKE_COMMAND}
                        "-DYR=$<TARGET_FILE:xxyara_cli>"
                        "-DREFERENCE_YR=${XXYARA_REFERENCE_YR}"
                        "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-check-deps"
                        -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_check_deps.cmake")
                add_test(NAME xxyara_cli_check_followup
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_check_followup.py"
                        "--reference" "${XXYARA_REFERENCE_YR}"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/cli-check-followup")
                add_test(NAME xxyara_cli_deps_config_followup
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_deps_config_followup.py"
                        "--reference" "${XXYARA_REFERENCE_YR}"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/cli-deps-config-followup")
                set(cli_token_ownership_source
                    "${CMAKE_CURRENT_BINARY_DIR}/cli_token_ownership_test.c")
                add_custom_command(OUTPUT "${cli_token_ownership_source}"
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_cli_token_ownership_test.py"
                        "--source" "${CMAKE_CURRENT_SOURCE_DIR}/src/cli.c"
                        "--output" "${cli_token_ownership_source}"
                    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/cli.c"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_cli_token_ownership_test.py"
                    VERBATIM)
                add_executable(test_cli_token_ownership "${cli_token_ownership_source}")
                set_target_properties(test_cli_token_ownership PROPERTIES
                    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
                add_test(NAME xxyara_cli_token_ownership
                    COMMAND "$<TARGET_FILE:test_cli_token_ownership>")
                if(WIN32)
                    add_test(NAME xxyara_cli_diagnostic_colors_windows
                        COMMAND "${Python3_EXECUTABLE}"
                            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_diagnostic_colors_windows.py"
                            "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                            "--reference-yr" "${XXYARA_REFERENCE_YR}"
                            "--output-dir" "${CMAKE_CURRENT_BINARY_DIR}/cli-diagnostic-colors")
                endif()
                add_test(NAME xxyara_archive_or_chain
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_archive_or_chain.py"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/archive-or-chain")
                set_tests_properties(xxyara_archive_or_chain PROPERTIES
                    LABELS "archive" TIMEOUT 90)
                add_test(NAME xxyara_archive_quantifier
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_archive_quantifier.py"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/archive-quantifier")
                set_tests_properties(xxyara_archive_quantifier PROPERTIES
                    LABELS "archive" TIMEOUT 120)
                add_test(NAME xxyara_archive_pattern_followup
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_archive_pattern_followup.py"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/archive-pattern-followup")
                set_tests_properties(xxyara_archive_pattern_followup PROPERTIES
                    LABELS "archive" TIMEOUT 120)
                add_test(NAME xxyara_archive_module_followup
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_archive_module_followup.py"
                        "--reference" "${XXYARA_REFERENCE_YR}"
                        "--candidate" "$<TARGET_FILE:xxyara_cli>"
                        "--work" "${CMAKE_CURRENT_BINARY_DIR}/archive-module-followup")
                set_tests_properties(xxyara_archive_module_followup PROPERTIES
                    LABELS "archive" TIMEOUT 180)
                foreach(_lastmile integer composed switch_scoped)
                    add_test(NAME xxyara_archive_${_lastmile}_lastmile
                        COMMAND "${Python3_EXECUTABLE}"
                            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_archive_${_lastmile}_lastmile.py"
                            "--reference-yr" "${XXYARA_REFERENCE_YR}"
                            "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                            "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/archive-${_lastmile}-lastmile")
                    set_tests_properties(xxyara_archive_${_lastmile}_lastmile PROPERTIES
                        LABELS "archive" TIMEOUT 180)
                endforeach()
                add_test(NAME xxyara_archive_large_reference
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_archive_large.py"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/archive-large-reference")
                set_tests_properties(xxyara_archive_large_reference PROPERTIES
                    LABELS "archive;slow" RUN_SERIAL TRUE TIMEOUT 900)
                add_test(NAME xxyara_config_reference
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/configuration_sweep.py"
                        "--reference-yr" "${XXYARA_REFERENCE_YR}"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--output-dir" "${CMAKE_CURRENT_BINARY_DIR}/config-reference")
                # The Unicode tables do not depend on optional modules, so the
                # test compares against the official default build when known.
                if(XXYARA_REFERENCE_DEFAULT_YR)
                    set(XXYARA_UNICODE_REFERENCE_YR "${XXYARA_REFERENCE_DEFAULT_YR}")
                else()
                    set(XXYARA_UNICODE_REFERENCE_YR "${XXYARA_REFERENCE_YR}")
                endif()
                add_test(NAME xxyara_config_unicode_reference
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_debug_unicode.py"
                        "--reference-yr" "${XXYARA_UNICODE_REFERENCE_YR}"
                        "--candidate-yr" "$<TARGET_FILE:xxyara_cli>"
                        "--output" "${CMAKE_CURRENT_BINARY_DIR}/debug_unicode_reference.h"
                        "--work-dir" "${CMAKE_CURRENT_BINARY_DIR}/debug-unicode-reference")
            endif()
            add_test(NAME xxyara_reference
                COMMAND ${CMAKE_COMMAND}
                    "-DYR=$<TARGET_FILE:xxyara_cli>"
                    "-DREFERENCE_YR=${XXYARA_REFERENCE_YR}"
                    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/reference-comparison"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_reference.cmake")
        endif()
        if(XXYARA_ENABLE_VBA AND XXYARA_REFERENCE_VBA_YR)
            add_test(NAME xxyara_reference_vba
                COMMAND ${CMAKE_COMMAND}
                    "-DYR=$<TARGET_FILE:xxyara_cli>"
                    "-DREFERENCE_YR=${XXYARA_REFERENCE_VBA_YR}"
                    "-DFIXTURE_WRITER=$<TARGET_FILE:test_module_vba>"
                    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/vba-reference-comparison"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vba_reference.cmake")
        endif()
    endif()
endif()

if(MSVC)
    foreach(_executable xxyara_cli xxyara_console xxyara_test_cli test_xxyara test_api test_serialization
            test_cli_regex test_native_regex test_crx_crypto_windows)
        if(TARGET ${_executable})
            target_link_options(${_executable} PRIVATE /STACK:8388608)
        endif()
    endforeach()
endif()

if(XXYARA_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

if(XXYARA_NO_CRT)
    # xxfclib's Windows C runtime under the standard names, for /NODEFAULTLIB
    # links only: it defines malloc, memcpy, printf's back ends and the entry
    # points, so a program that also links Microsoft's runtime must not use it.
    set(_xxyara_crt_sources
        src/crt/platforms/xx_crt_windows.c
        src/crt/platforms/xx_crt_stdio_windows.c
        src/crt/platforms/xx_crt_args_windows.c
        src/crt/platforms/xx_crt_entry_windows.c
        src/crt/platforms/xx_crt_main_windows.c
        src/crt/platforms/xx_crt_wmain_windows.c
        src/crt/platforms/xx_crt_dll_windows.c
        src/crt/platforms/xx_crt_dllmain_windows.c
        src/crt/platforms/xx_crt_tls_windows.c
        )
    if(CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^(X86|x86)$")
        list(APPEND _xxyara_crt_sources src/crt/platforms/xx_crt_helpers_windows_x86.asm)
        set_source_files_properties(
            "${XXYARA_XXFCLIB_SOURCE_DIR}/src/crt/platforms/xx_crt_helpers_windows_x86.asm"
            PROPERTIES COMPILE_OPTIONS /safeseh)
    else()
        list(APPEND _xxyara_crt_sources src/platforms/xx_chkstk_windows_x64.asm)
    endif()
    list(TRANSFORM _xxyara_crt_sources PREPEND "${XXYARA_XXFCLIB_SOURCE_DIR}/")
    add_library(xxyara_crt STATIC ${_xxyara_crt_sources})
    add_library(xxfclib::crt ALIAS xxyara_crt)
    target_link_libraries(xxyara_crt PUBLIC xxfclib::xxfclib)
    set_target_properties(xxyara_crt PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

    # Every executable and the DLL of this tree links CRT-free, except the C++
    # example (it uses the C++ standard library and exceptions, which need
    # Microsoft's runtime) and the differential test, which compares
    # xxfclib's runtime with Microsoft's and therefore links the real one.
    set(_xxyara_crt_hosted xxyara_example_cpp test_crt_ucrt_diff test_ms_log2_ucrt test_crt_probe_ucrt)
    get_property(_xxyara_crt_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    if(TARGET xxyara_example_c_static OR TARGET xxyara_example_cpp)
        get_property(_xxyara_crt_example_targets DIRECTORY examples PROPERTY BUILDSYSTEM_TARGETS)
        list(APPEND _xxyara_crt_targets ${_xxyara_crt_example_targets})
    endif()
    foreach(_xxyara_crt_target IN LISTS _xxyara_crt_targets)
        get_target_property(_xxyara_crt_type ${_xxyara_crt_target} TYPE)
        if((_xxyara_crt_type STREQUAL "EXECUTABLE" OR _xxyara_crt_type STREQUAL "SHARED_LIBRARY")
           AND NOT _xxyara_crt_target IN_LIST _xxyara_crt_hosted)
            target_link_libraries(${_xxyara_crt_target} PRIVATE xxyara_crt)
            # LNK4210 reports the .CRT section without a C runtime: here it
            # holds only TLS callbacks (.CRT$XL*), which the TLS directory of
            # xx_crt_tls_windows.c calls; C has no static initializers.
            target_link_options(${_xxyara_crt_target} PRIVATE /NODEFAULTLIB /IGNORE:4210)
        endif()
    endforeach()
endif()
