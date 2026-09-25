# ulpx-config.cmake - Auto-discovered by CMake's find_package(ulpx)
get_filename_component(ULPX_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)
set(ULPX_ROOT_DIR "${ULPX_CMAKE_DIR}")

find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(NOT TARGET ulpx-demo)
    add_custom_target(ulpx-demo
        COMMAND ${Python3_EXECUTABLE} "${ULPX_ROOT_DIR}/scripts/demo.py"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Launching ULPF-X Security Firewall & Profiler"
        USES_TERMINAL
    )
endif()

if(NOT TARGET ulpx-test)
    add_custom_target(ulpx-test
        COMMAND ${Python3_EXECUTABLE} "${ULPX_ROOT_DIR}/scripts/audit.py"
        WORKING_DIRECTORY "${ULPX_ROOT_DIR}"
        COMMENT "Executing ULPF-X Continuous Audit Engine"
        USES_TERMINAL
    )
endif()

message(STATUS "ULPF-X Telemetry Guard active for project: ${CMAKE_PROJECT_NAME}")
