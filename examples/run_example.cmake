# Runs one example (COMMAND: program and arguments separated by |) and compares its standard output with the EXPECTED file.
# Line endings are normalised, so CRLF output on Windows compares equal.
if(NOT DEFINED COMMAND OR NOT DEFINED EXPECTED)
    message(FATAL_ERROR "COMMAND and EXPECTED are required")
endif()
string(REPLACE "|" ";" COMMAND "${COMMAND}")
execute_process(COMMAND ${COMMAND}
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE errors TIMEOUT 120)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "example failed (${status}):\n${errors}\n${output}")
endif()
file(READ "${EXPECTED}" expected)
string(REPLACE "\r\n" "\n" output "${output}")
string(REPLACE "\r\n" "\n" expected "${expected}")
if(NOT output STREQUAL expected)
    message(FATAL_ERROR "unexpected output:\n${output}\nexpected:\n${expected}")
endif()
message(STATUS "example output matches ${EXPECTED}")
