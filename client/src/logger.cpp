#include "minidrive/client/logger.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/null_sink.h>

#include <vector>

namespace minidrive::client
{

    Logger::Logger(const std::optional<std::filesystem::path> &path)
    {
        try
        {
            std::vector<spdlog::sink_ptr> sinks;
            if (path)
            {
                sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true));
            }
            else
            {
                sinks.push_back(std::make_shared<spdlog::sinks::null_sink_mt>());
            }
            logger_ = std::make_shared<spdlog::logger>("client", sinks.begin(), sinks.end());
            logger_->set_pattern("%Y-%m-%d %H:%M:%S [%l] %v");
            logger_->set_level(spdlog::level::info);
        }
        catch (...)
        {
            logger_.reset();
        }
    }

} // namespace minidrive::client
