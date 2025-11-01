#include "minidrive/server/transfer_registry.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <vector>

#include <nlohmann/json.hpp>

#include "minidrive/crypto.hpp"

namespace minidrive::server
{

    namespace
    {
        constexpr auto kMetadataDir = ".minidrive/uploads";

        nlohmann::json to_json(const UploadState &state)
        {
            return {
                {"transfer_id", state.transfer_id},
                {"identity", state.identity},
                {"final_path", state.final_path.generic_string()},
                {"temp_path", state.temp_path.generic_string()},
                {"file_size", state.file_size},
                {"chunk_size", state.chunk_size},
                {"bytes_written", state.bytes_written},
                {"root_hash", state.root_hash},
                {"last_update", std::chrono::duration_cast<std::chrono::seconds>(state.last_update.time_since_epoch()).count()},
            };
        }

        UploadState state_from_json(const nlohmann::json &json)
        {
            UploadState state{};
            state.transfer_id = json.at("transfer_id").get<std::string>();
            state.identity = json.at("identity").get<std::string>();
            state.final_path = json.at("final_path").get<std::string>();
            state.temp_path = json.at("temp_path").get<std::string>();
            state.file_size = json.value("file_size", 0ULL);
            state.chunk_size = json.value("chunk_size", 0ULL);
            state.bytes_written = json.value("bytes_written", 0ULL);
            state.root_hash = json.value("root_hash", std::string{});
            const auto seconds = json.value("last_update", 0LL);
            state.last_update = std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
            return state;
        }

    } // namespace

    TransferRegistry::TransferRegistry(std::filesystem::path storage_root)
        : registry_dir_(std::move(storage_root) / kMetadataDir)
    {
        std::filesystem::create_directories(registry_dir_);
        load_existing();
    }

    ResumeInfo TransferRegistry::create_or_resume(const std::string &identity, const std::filesystem::path &target_path,
                                                  std::uint64_t file_size, std::uint64_t chunk_size,
                                                  const std::string &root_hash, bool resume_requested)
    {
        std::lock_guard lock(mutex_);
        load_existing();

        auto now = std::chrono::system_clock::now();

        // Look for matching existing upload
        auto existing_it = std::find_if(uploads_.begin(), uploads_.end(), [&](const auto &item)
                                        {
        const auto& state = item.second;
        return state.identity == identity && state.final_path == target_path && state.root_hash == root_hash; });

        if (resume_requested && existing_it != uploads_.end())
        {
            auto &existing = existing_it->second;
            const auto expected_chunk = chunk_size == 0 ? existing.chunk_size : chunk_size;
            if (existing.file_size != file_size || existing.chunk_size != expected_chunk || existing.root_hash != root_hash)
            {
                std::error_code ec;
                std::filesystem::remove(existing.temp_path, ec);
                const auto existing_transfer_id = existing_it->first;
                remove_state(existing_transfer_id);
                uploads_.erase(existing_it);
                existing_it = uploads_.end();
            }
            else
            {
                existing.last_update = now;
                persist_state(existing);
                return {.state = existing, .resumed = true};
            }
        }

        if (existing_it != uploads_.end())
        {
            // Remove stale entry
            std::filesystem::remove(existing_it->second.temp_path);
            remove_state(existing_it->first);
            uploads_.erase(existing_it);
        }

        UploadState state{};
        state.transfer_id = generate_transfer_id();
        state.identity = identity;
        state.final_path = target_path;
        state.temp_path = target_path;
        state.temp_path += ".part";
        state.file_size = file_size;
        state.chunk_size = chunk_size == 0 ? (1u << 20) : chunk_size;
        state.bytes_written = 0;
        state.root_hash = root_hash;
        state.last_update = now;

        std::filesystem::create_directories(state.temp_path.parent_path());
        std::ofstream file(state.temp_path, std::ios::binary | std::ios::trunc);
        file.close();

        uploads_[state.transfer_id] = state;
        persist_state(state);
        return {.state = state, .resumed = false};
    }

    bool TransferRegistry::append_chunk(const std::string &transfer_id, std::uint64_t offset,
                                        const std::vector<std::byte> &data, const std::string &chunk_hash,
                                        std::string &error_message)
    {
        std::lock_guard lock(mutex_);
        auto it = uploads_.find(transfer_id);
        if (it == uploads_.end())
        {
            error_message = "Unknown transfer";
            return false;
        }

        auto &state = it->second;
        if (offset != state.bytes_written)
        {
            error_message = "Unexpected chunk offset";
            return false;
        }

        if (state.bytes_written + static_cast<std::uint64_t>(data.size()) > state.file_size)
        {
            error_message = "Chunk exceeds declared file size";
            return false;
        }

        const auto computed_hash = crypto::hash_bytes(data);
        if (computed_hash != chunk_hash)
        {
            error_message = "Chunk hash mismatch";
            return false;
        }

        std::fstream file(state.temp_path, std::ios::binary | std::ios::in | std::ios::out);
        if (!file.is_open())
        {
            file.open(state.temp_path, std::ios::binary | std::ios::out | std::ios::trunc);
        }
        file.seekp(static_cast<std::streamoff>(offset));
        file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
        file.flush();

        state.bytes_written += static_cast<std::uint64_t>(data.size());
        state.last_update = std::chrono::system_clock::now();
        persist_state(state);
        return true;
    }

    bool TransferRegistry::commit(const std::string &transfer_id, const std::string &final_hash,
                                  std::string &error_message)
    {
        std::lock_guard lock(mutex_);
        auto it = uploads_.find(transfer_id);
        if (it == uploads_.end())
        {
            error_message = "Unknown transfer";
            return false;
        }
        auto state = it->second;
        if (state.bytes_written != state.file_size)
        {
            error_message = "Upload incomplete";
            return false;
        }

        if (crypto::hash_file(state.temp_path) != final_hash)
        {
            error_message = "File hash mismatch";
            return false;
        }

        std::filesystem::create_directories(state.final_path.parent_path());
        if (std::filesystem::exists(state.final_path))
        {
            std::filesystem::remove(state.final_path);
        }
        std::filesystem::rename(state.temp_path, state.final_path);
        remove_state(transfer_id);
        uploads_.erase(it);
        return true;
    }

    std::optional<UploadState> TransferRegistry::find(const std::string &transfer_id) const
    {
        std::lock_guard lock(mutex_);
        auto it = uploads_.find(transfer_id);
        if (it != uploads_.end())
        {
            return it->second;
        }
        return std::nullopt;
    }

    void TransferRegistry::cleanup_expired(std::chrono::seconds max_age)
    {
        std::lock_guard lock(mutex_);
        auto now = std::chrono::system_clock::now();
        for (auto it = uploads_.begin(); it != uploads_.end();)
        {
            if (now - it->second.last_update > max_age)
            {
                std::filesystem::remove(it->second.temp_path);
                remove_state(it->first);
                it = uploads_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    std::filesystem::path TransferRegistry::metadata_path(const std::string &transfer_id) const
    {
        return registry_dir_ / (transfer_id + ".json");
    }

    void TransferRegistry::load_existing()
    {
        if (loaded_)
        {
            return;
        }
        loaded_ = true;
        for (const auto &entry : std::filesystem::directory_iterator(registry_dir_))
        {
            if (!entry.is_regular_file())
            {
                continue;
            }
            std::ifstream in(entry.path());
            if (!in.is_open())
            {
                continue;
            }
            nlohmann::json json;
            in >> json;
            auto state = state_from_json(json);
            uploads_[state.transfer_id] = state;
        }
    }

    void TransferRegistry::persist_state(const UploadState &state) const
    {
        const auto path = metadata_path(state.transfer_id);
        nlohmann::json json = to_json(state);
        std::ofstream out(path, std::ios::trunc);
        out << json.dump(2);
    }

    void TransferRegistry::remove_state(const std::string &transfer_id)
    {
        std::filesystem::remove(metadata_path(transfer_id));
    }

    std::string TransferRegistry::generate_transfer_id()
    {
        static std::mt19937_64 rng{std::random_device{}()};
        static std::uniform_int_distribution<std::uint64_t> dist;
        std::uint64_t value = dist(rng);
        std::ostringstream oss;
        oss << std::hex << value;
        return oss.str();
    }

} // namespace minidrive::server
