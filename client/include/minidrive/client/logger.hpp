#pragma once

#include <filesystem>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

namespace minidrive::client
{

    class Logger
    {
    public:
        explicit Logger(const std::optional<std::filesystem::path> &path);

        template <typename... Args>
        void log(const std::string &tag, Args &&...args)
        {
            if (!logger_)
            {
                return;
            }
            spdlog::fmt_lib::memory_buffer buf;
            (spdlog::fmt_lib::format_to(std::back_inserter(buf), "{}", std::forward<Args>(args)), ...);
            logger_->info("[{}] {}", tag,
                          std::string(buf.data(), buf.size()));
        }

    private:
        std::shared_ptr<spdlog::logger> logger_;
    };

} // namespace minidrive::client
