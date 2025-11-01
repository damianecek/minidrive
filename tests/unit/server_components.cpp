#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "minidrive/crypto.hpp"
#include "minidrive/server/filesystem.hpp"
#include "minidrive/server/transfer_registry.hpp"

using namespace minidrive;
using namespace minidrive::server;

namespace
{

    void cleanup_path(const std::filesystem::path &path)
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }

    void test_transfer_registry_basic()
    {
        const auto temp_root = std::filesystem::temp_directory_path() / "minidrive_transfer_test";
        cleanup_path(temp_root);
        std::filesystem::create_directories(temp_root);

        TransferRegistry registry(temp_root);
        const auto target = temp_root / "uploads" / "file.bin";
        const std::string root_hash = "root-hash";

        auto create = registry.create_or_resume("alice", target, 6, 3, root_hash, false);
        assert(create.state.bytes_written == 0);
        assert(!create.resumed);

        const std::vector<std::byte> chunk1 = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        const auto chunk1_hash = crypto::hash_bytes(chunk1);
        std::string error;
        assert(registry.append_chunk(create.state.transfer_id, 0, chunk1, chunk1_hash, error));
        assert(error.empty());

        const std::vector<std::byte> chunk2 = {std::byte{0x04}, std::byte{0x05}, std::byte{0x06}};
        const auto chunk2_hash = crypto::hash_bytes(chunk2);
        assert(registry.append_chunk(create.state.transfer_id, 3, chunk2, chunk2_hash, error));

        auto resume = registry.create_or_resume("alice", target, 6, 3, root_hash, true);
        assert(resume.resumed);
        assert(resume.state.bytes_written == 6);

        const auto commit_hash = crypto::hash_file(resume.state.temp_path);
        assert(registry.commit(create.state.transfer_id, commit_hash, error));
        assert(std::filesystem::exists(target));

        cleanup_path(temp_root);
    }

    void test_filesystem_paths()
    {
        const auto temp_root = std::filesystem::temp_directory_path() / "minidrive_fs_test";
        cleanup_path(temp_root);
        Filesystem fs(temp_root);
        auto session = fs.prepare_session_paths("alice", false);
        fs.create_directory(session, "docs");
        const auto new_file = fs.resolve_for_new_entry(session, "docs/file.txt");
        assert(new_file == session.root / "docs" / "file.txt");

        bool caught = false;
        try
        {
            (void)fs.resolve(session, "../forbidden");
        }
        catch (const std::exception &)
        {
            caught = true;
        }
        assert(caught);

        cleanup_path(temp_root);
    }

    void test_transfer_registry_resume_mismatch()
    {
        const auto temp_root = std::filesystem::temp_directory_path() / "minidrive_transfer_resume";
        cleanup_path(temp_root);
        std::filesystem::create_directories(temp_root);

        TransferRegistry registry(temp_root);
        const auto target = temp_root / "uploads" / "file.bin";
        const std::string root_hash = "root-hash";

        auto create = registry.create_or_resume("bob", target, 10, 4, root_hash, false);
        assert(!create.resumed);

        auto resume = registry.create_or_resume("bob", target, 12, 4, root_hash, true);
        assert(!resume.resumed);
        assert(resume.state.bytes_written == 0);
        assert(resume.state.transfer_id != create.state.transfer_id);

        cleanup_path(temp_root);
    }

    void test_transfer_registry_cleanup_expired()
    {
        const auto temp_root = std::filesystem::temp_directory_path() / "minidrive_transfer_cleanup";
        cleanup_path(temp_root);
        std::filesystem::create_directories(temp_root);

        TransferRegistry registry(temp_root);
        const auto target = temp_root / "uploads" / "file.bin";
        auto info = registry.create_or_resume("carol", target, 6, 3, "hash", false);
        assert(!info.resumed);

        const auto metadata_dir = temp_root / ".minidrive/uploads";
        for (const auto &entry : std::filesystem::directory_iterator(metadata_dir))
        {
            if (!entry.is_regular_file())
            {
                continue;
            }
            nlohmann::json meta;
            {
                std::ifstream in(entry.path());
                in >> meta;
            }
            meta["last_update"] = 0;
            std::ofstream out(entry.path(), std::ios::trunc);
            out << meta.dump();
        }

        TransferRegistry reloaded(temp_root);
        reloaded.cleanup_expired(std::chrono::seconds(1));

        if (std::filesystem::exists(metadata_dir))
        {
            for (const auto &entry : std::filesystem::directory_iterator(metadata_dir))
            {
                assert(!entry.is_regular_file());
            }
        }

        cleanup_path(temp_root);
    }

} // namespace

void run_server_component_tests()
{
    test_transfer_registry_basic();
    test_filesystem_paths();
    test_transfer_registry_resume_mismatch();
    test_transfer_registry_cleanup_expired();
}
