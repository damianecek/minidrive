#include "minidrive/server/session.hpp"

#include <filesystem>
#include <vector>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "minidrive/crypto.hpp"
#include "session_common.hpp"

namespace minidrive::server
{

    void Session::handle_sync_enumerate(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto request = envelope.payload.get<minidrive::protocol::PathRequest>();
            const auto base = services_.filesystem.resolve(session_paths_, request.path);
            std::vector<minidrive::protocol::FileMetadata> entries;
            std::error_code ec;
            auto root_time = std::filesystem::last_write_time(base, ec);
            if (ec)
            {
                root_time = std::filesystem::file_time_type::clock::now();
            }
            minidrive::protocol::FileMetadata root_meta{
                .path = ".",
                .size = 0,
                .modified_time = session_common::to_unix_time(root_time),
                .is_directory = true,
                .content_hash = std::nullopt,
            };
            entries.push_back(root_meta);

            for (std::filesystem::recursive_directory_iterator it(base); it != std::filesystem::recursive_directory_iterator(); ++it)
            {
                ec.clear();
                const auto rel_path = session_common::relative_path_or_dot(base, it->path());
                minidrive::protocol::FileMetadata metadata{};
                metadata.path = rel_path;
                metadata.is_directory = it->is_directory(ec);
                if (ec)
                {
                    metadata.is_directory = false;
                }
                std::uint64_t size = 0;
                if (!metadata.is_directory)
                {
                    auto file_size = it->file_size(ec);
                    if (!ec)
                    {
                        size = static_cast<std::uint64_t>(file_size);
                    }
                }
                metadata.size = size;
                auto modified = std::filesystem::last_write_time(it->path(), ec);
                if (ec)
                {
                    modified = std::filesystem::file_time_type::clock::now();
                }
                metadata.modified_time = session_common::to_unix_time(modified);
                if (!metadata.is_directory)
                {
                    try
                    {
                        metadata.content_hash = minidrive::crypto::hash_file(it->path());
                    }
                    catch (const std::exception &)
                    {
                        metadata.content_hash.reset();
                    }
                }
                entries.push_back(std::move(metadata));
            }

            nlohmann::json payload;
            payload["entries"] = entries;
            send_response(session_common::make_ok_response(std::move(payload), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            spdlog::error("SYNC_ENUMERATE failed for {}: {}", session_paths_.identity, ex.what());
            send_error(minidrive::ErrorCode::InternalError, ex.what(), envelope.request_id);
        }
    }

    void Session::handle_sync_apply(const minidrive::protocol::RequestEnvelope &envelope)
    {
        if (!authenticated_)
        {
            send_error(minidrive::ErrorCode::AuthenticationRequired, "Authentication required", envelope.request_id);
            return;
        }
        try
        {
            const auto plan = envelope.payload.get<minidrive::protocol::SyncPlan>();
            for (const auto &entry : plan.entries)
            {
                if (entry.action == minidrive::protocol::SyncAction::DeleteRemote)
                {
                    try
                    {
                        const auto target = services_.filesystem.resolve(session_paths_, entry.metadata.path);
                        if (entry.metadata.is_directory)
                        {
                            std::filesystem::remove_all(target);
                        }
                        else
                        {
                            std::filesystem::remove(target);
                        }
                    }
                    catch (const std::exception &)
                    {
                        // Ignore missing targets during delete operations
                    }
                }
            }
            send_response(session_common::make_ok_response(nlohmann::json::object(), envelope.request_id));
        }
        catch (const std::exception &ex)
        {
            spdlog::error("SYNC_APPLY failed for {}: {}", session_paths_.identity, ex.what());
            send_error(minidrive::ErrorCode::InvalidPayload, ex.what(), envelope.request_id);
        }
    }

} // namespace minidrive::server
