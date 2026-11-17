# xxyara examples: the C example linked statically and against the shared library, and the C++ example.
# With tests enabled, each example (and the Python example, when Python 3 is found) scans data/sample.txt
# with data/rules.yar and must print data/expected.txt.

add_executable(xxyara_example_c_static c/scan.c)
target_link_libraries(xxyara_example_c_static PRIVATE xxyara::xxyara)
set_target_properties(xxyara_example_c_static PROPERTIES OUTPUT_NAME scan_static)

enable_language(CXX)
add_executable(xxyara_example_cpp cpp/scan.cpp)
target_link_libraries(xxyara_example_cpp PRIVATE xxyara::xxyara)
set_target_properties(xxyara_example_cpp PROPERTIES OUTPUT_NAME scan_cpp CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)

if(TARGET xxyara_shared)
    add_executable(xxyara_example_c_shared c/scan.c)
    target_link_libraries(xxyara_example_c_shared PRIVATE xxyara::shared)
    set_target_properties(xxyara_example_c_shared PROPERTIES OUTPUT_NAME scan_shared)
    if(WIN32)
        # Put the DLL next to the example so that it runs from its build folder.
        add_custom_command(TARGET xxyara_example_c_shared POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:xxyara_shared>" "$<TARGET_FILE_DIR:xxyara_example_c_shared>")
    endif()
endif()

if(MSVC)
    foreach(_example xxyara_example_c_static xxyara_example_c_shared xxyara_example_cpp)
        if(TARGET ${_example})
            target_link_options(${_example} PRIVATE /STACK:8388608)
        endif()
    endforeach()
endif()

if(XXYARA_BUILD_TESTS AND BUILD_TESTING)
    set(_example_data "${CMAKE_CURRENT_SOURCE_DIR}/data")
    foreach(_example xxyara_example_c_static xxyara_example_c_shared xxyara_example_cpp)
        if(TARGET ${_example})
            add_test(NAME ${_example}
                COMMAND ${CMAKE_COMMAND}
                    "-DCOMMAND=$<TARGET_FILE:${_example}>|${_example_data}/rules.yar|${_example_data}/sample.txt"
                    "-DEXPECTED=${_example_data}/expected.txt"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/run_example.cmake")
        endif()
    endforeach()
    if(TARGET xxyara_shared)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            add_test(NAME xxyara_example_python
                COMMAND ${CMAKE_COMMAND}
                    "-DCOMMAND=${Python3_EXECUTABLE}|-I|${CMAKE_CURRENT_SOURCE_DIR}/python/scan.py|${_example_data}/rules.yar|${_example_data}/sample.txt|$<TARGET_FILE:xxyara_shared>"
                    "-DEXPECTED=${_example_data}/expected.txt"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/run_example.cmake")
        endif()
    endif()
endif()
