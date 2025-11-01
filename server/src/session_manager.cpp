#include "minidrive/server/session_manager.hpp"

#include <algorithm>

#include "minidrive/server/session.hpp"

namespace minidrive::server
{

    bool SessionManager::try_register(const std::string &identity, const std::shared_ptr<Session> &session)
    {
        std::lock_guard lock(mutex_);
        auto &list = sessions_[identity];
        list.erase(std::remove_if(list.begin(), list.end(),
                                  [](const std::weak_ptr<Session> &weak)
                                  { return weak.expired(); }),
                   list.end());
        list.push_back(session);
        return true;
    }

    void SessionManager::unregister(const std::string &identity, const Session *session)
    {
        std::lock_guard lock(mutex_);
        auto it = sessions_.find(identity);
        if (it == sessions_.end())
        {
            return;
        }
        auto &list = it->second;
        list.erase(std::remove_if(list.begin(), list.end(),
                                  [session](const std::weak_ptr<Session> &weak)
                                  {
                                      auto ptr = weak.lock();
                                      return !ptr || ptr.get() == session;
                                  }),
                   list.end());
        if (list.empty())
        {
            sessions_.erase(it);
        }
    }

} // namespace minidrive::server
