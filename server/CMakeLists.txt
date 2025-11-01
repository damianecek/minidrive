add_executable(minidrive_server
    src/main.cpp
    src/server.cpp
    src/session.cpp
    src/session_manager.cpp
    src/user_store.cpp
    src/filesystem.cpp
    src/transfer_registry.cpp
)

target_include_directories(minidrive_server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(minidrive_server
    PRIVATE
        minidrive_shared
        minidrive_warnings
        spdlog::spdlog
)

set_target_properties(minidrive_server PROPERTIES OUTPUT_NAME server)

