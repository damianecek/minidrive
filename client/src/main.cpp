#include <iostream>

#include "minidrive/client/config.hpp"
#include "minidrive/client/logger.hpp"
#include "minidrive/client/session.hpp"

int main(int argc, char *argv[])
{
    try
    {
        const auto config = minidrive::client::parse_arguments(argc, argv);
        minidrive::client::Logger logger(config.log_path);
        minidrive::client::ClientSession session(config, std::move(logger));
        return session.run();
    }
    catch (const std::exception &ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        return 1;
    }
}
