add_executable(minidrive_client
    src/config.cpp
    src/logger.cpp
    src/main.cpp
    src/session.cpp
    src/session_commands.cpp
    src/session_sync.cpp
    src/session_transfers.cpp
    src/transfer_state_store.cpp
)

target_include_directories(minidrive_client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(minidrive_client
    PRIVATE
        minidrive_shared
        minidrive_warnings
        spdlog::spdlog
)

set_target_properties(minidrive_client PROPERTIES OUTPUT_NAME client)
