find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_executable(minidrive_integration_smoke
    integration/smoke.cpp
)

target_link_libraries(minidrive_integration_smoke
    PRIVATE
        minidrive_shared
        minidrive_warnings
)

set_target_properties(minidrive_integration_smoke PROPERTIES OUTPUT_NAME integration_smoke)

add_executable(minidrive_shared_unit
    unit/shared_protocol.cpp
    unit/server_components.cpp
)

target_link_libraries(minidrive_shared_unit
    PRIVATE
        minidrive_shared
        minidrive_warnings
)

target_include_directories(minidrive_shared_unit
    PRIVATE
        ${CMAKE_SOURCE_DIR}/server/include
)

target_sources(minidrive_shared_unit
    PRIVATE
        ${CMAKE_SOURCE_DIR}/server/src/filesystem.cpp
        ${CMAKE_SOURCE_DIR}/server/src/transfer_registry.cpp
)

set_target_properties(minidrive_shared_unit PROPERTIES OUTPUT_NAME shared_unit_tests)

add_test(
    NAME minidrive_requirements
    COMMAND Python3::Interpreter
        ${CMAKE_CURRENT_SOURCE_DIR}/integration/requirements_test.py
        --server $<TARGET_FILE:minidrive_server>
        --client $<TARGET_FILE:minidrive_client>
)
