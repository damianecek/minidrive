#pragma once

#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <string>

namespace minidrive::server
{

    class Session;

    class SessionManager
    {
    public:
        bool try_register(const std::string &identity, const std::shared_ptr<Session> &session);
        void unregister(const std::string &identity, const Session *session);

    private:
        std::mutex mutex_;
        std::map<std::string, std::vector<std::weak_ptr<Session>>> sessions_;
    };

} // namespace minidrive::server
