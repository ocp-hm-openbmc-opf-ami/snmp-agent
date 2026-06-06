#include "config.h"

#include "snmp_agent_serialize.hpp"

#include "snmp_agent_client.hpp"
#include "snmp_user_create.hpp"
#include "snmp_user_manager.hpp"

#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>

// Register class version
// From cereal documentation;
// "This macro should be placed at global scope"
CEREAL_CLASS_VERSION(phosphor::snmp::communityStr::CommunityStrManager,
                     CLASS_VERSION);

namespace phosphor
{
namespace snmp
{
namespace communityStr
{

/** @brief Function required by Cereal to perform serialization.
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to Cereal archive.
 *  @param[in] manager - const reference to snmp manager info.
 *  @param[in] version - Class version that enables handling
 *                       a serialized data across code levels
 */
template <class Archive>
void save(Archive& archive, const CommunityStrManager& manager,
          const std::uint32_t /*version*/)
{
    archive(manager.communityString(), manager.readWritePermission(),
            manager.communityProfile());
}

/** @brief Function required by Cereal to perform deserialization.
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to Cereal archive.
 *  @param[in] manager - reference to snmp manager info.
 *  @param[in] version - Class version that enables handling
 *                       a serialized data across code levels
 */
template <class Archive>
void load(Archive& archive, CommunityStrManager& manager,
          const std::uint32_t /*version*/)
{
    std::string communityString{};
    std::string readWritePermission{};
    std::string communityProfile{};

    archive(communityString, readWritePermission, communityProfile);

    manager.communityString(communityString);
    manager.readWritePermission(readWritePermission);
    manager.communityProfile(communityProfile);
}

fs::path serialize(const std::string communityName,
                   const CommunityStrManager& manager, const fs::path& dir)
{
    fs::path fileName = dir;
    fs::create_directories(dir);
    fileName /= communityName;
    std::ofstream os(fileName.string(), std::ios::binary);
    if (!os.is_open())
    {
        std::cerr << "Error: Could not open file " << fileName << std::endl;
        fileName = "";
        return fileName;
    }
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(manager);
    return fileName;
}

bool deserialize(const fs::path& path, CommunityStrManager& manager)
{
    try
    {
        if (fs::exists(path))
        {
            std::ifstream is(path.c_str(), std::ios::in | std::ios::binary);
            if (!is.is_open())
            {
                std::cerr << "Error: Could not open file " << path << std::endl;
                return false;
            }
            cereal::BinaryInputArchive iarchive(is);
            iarchive(manager);
            return true;
        }
        return false;
    }
    catch (const cereal::Exception& e)
    {
        lg2::error("Deserialization failed: {ERROR}", "ERROR", e);
        std::error_code ec;
        fs::remove(path, ec);
        return false;
    }
    catch (const fs::filesystem_error& e)
    {
        return false;
    }
}
} // namespace communityStr
namespace user
{
/** @brief Function required by Cereal to perform serialization.
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to Cereal archive.
 *  @param[in] manager - const reference to snmp manager info.
 *  @param[in] version - Class version that enables handling
 *                       a serialized data across code levels
 */
template <class Archive>
void save(Archive& archive, const UserManager& manager,
          const std::uint32_t /*version*/)
{
    archive(manager.userName(), manager.password(), manager.encryption(),
            manager.algorithm(), manager.readWritePermission());
}

/** @brief Function required by Cereal to perform deserialization.
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to Cereal archive.
 *  @param[in] manager - reference to snmp manager info.
 *  @param[in] encryption - Class encryption that enables handling
 *                       a serialized data across code levels
 */
template <class Archive>
void load(Archive& archive, UserManager& manager,
          const std::uint32_t /*encryption*/)
{
    std::string userName{};
    std::string password{};
    std::string encryption{};
    std::string algorithm{};
    std::string readWritePermission{};

    archive(userName, password, encryption, algorithm, readWritePermission);

    manager.userName(userName);
    manager.password(password);
    manager.encryption(encryption);
    manager.algorithm(algorithm);
    manager.readWritePermission(readWritePermission);
}

fs::path serialize(const std::string userName, const UserManager& manager,
                   const fs::path& dir)
{
    fs::path fileName = dir;
    fs::create_directories(dir);
    fileName /= userName;

    std::ofstream os(fileName.string(), std::ios::binary);
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(manager);
    return fileName;
}

bool deserialize(const fs::path& path, UserManager& manager)
{
    try
    {
        if (fs::exists(path))
        {
            std::ifstream is(path.c_str(), std::ios::in | std::ios::binary);
            cereal::BinaryInputArchive iarchive(is);
            iarchive(manager);
            return true;
        }
        return false;
    }
    catch (const cereal::Exception& e)
    {
        lg2::error("Deserialization failed: {ERROR}", "ERROR", e);
        std::error_code ec;
        fs::remove(path, ec);
        return false;
    }
    catch (const fs::filesystem_error& e)
    {
        return false;
    }
}
} // namespace user
} // namespace snmp
} // namespace phosphor
