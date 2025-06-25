#pragma once
#include "xyz/openbmc_project/Object/Delete/server.hpp"
#include "xyz/openbmc_project/Snmp/CommunityStrManager/server.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <string>

std::vector<std::string> testing();
namespace phosphor
{
namespace snmp
{
namespace communityStr
{

class ConfManager;

using Ifaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Snmp::server::CommunityStrManager,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

using Id = size_t;

/** @class CommunityStrManager
 *  @brief represents the snmp CommunityStrManager configuration
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.CommunityStrManager Dbus interface.
 */
class CommunityStrManager : public Ifaces
{
  public:
    CommunityStrManager() = delete;
    CommunityStrManager(const CommunityStrManager&) = delete;
    CommunityStrManager& operator=(const CommunityStrManager&) = delete;
    CommunityStrManager(CommunityStrManager&&) = delete;
    CommunityStrManager& operator=(CommunityStrManager&&) = delete;
    virtual ~CommunityStrManager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent D-bus Object.
     *  @param[in] address - IPaddress/Hostname.
     *  @param[in] port - network port.
     */
    CommunityStrManager(sdbusplus::bus_t& bus, const char* objPath,
                        ConfManager& parent, const std::string& communityString,
                        const std::string& readWritePermission,
                        const std::string& communityProfile);

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent D-bus Object.
     */
    CommunityStrManager(sdbusplus::bus_t& bus, const char* objPath,
                        ConfManager& parent) :
        Ifaces(bus, objPath, Ifaces::action::defer_emit), parent(parent)
    {}

    /** @brief Update the address of the object.
     *
     *  @param[in] value - IP address
     *
     *  @return On success the updated IP address
     */
    std::string communityString(std::string value) override;

    /** @brief Update the port
     *
     *  @param[in] value - port number
     *
     *  @return On success the updated port number
     */

    /** @brief Update the SNMP version of the object.
     *
     *  @param[in] value - SNMP version
     *
     *  @return On success the updated SNMP version
     */
    std::string readWritePermission(std::string value) override;

    /** @brief Update the SNMP v3 user of the object.
     *
     *  @param[in] value - SNMP v3 username
     *
     *  @return On success the updated SNMP version
     */
    std::string communityProfile(std::string value) override;

    /** @brief Update the SNMP v3 user's password of the object.
     *
     *  @param[in] value - SNMP v3 password
     *
     *  @return On success the updated V3 user password
     */

    /** @brief Update the SNMP v3 readonlypermission of the object.
     *
     *  @param[in] value - SNMP v3 readonlypermission
     *
     *  @return On success the updated readonlypermission
     */

    /** @brief Update the algorithm of the object.
     *
     *  @param[in] value - v3 algorithm
     *
     *  @return On success the updated V3 Algorithm
     */

    /** @brief Update the encryption of the object.
     *
     *  @param[in] value - encryption
     *
     *  @return On success the updated encryption
     */

    using sdbusplus::xyz::openbmc_project::Snmp::server::CommunityStrManager::
        communityString;

    using sdbusplus::xyz::openbmc_project::Snmp::server::CommunityStrManager::
        readWritePermission;

    using sdbusplus::xyz::openbmc_project::Snmp::server::CommunityStrManager::
        communityProfile;

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    /** CommunityStrManager ID. */
    Id id;

  private:
    /** @brief Parent D-Bus Object. */
    ConfManager& parent;
};
} // namespace communityStr
} // namespace snmp
} // namespace phosphor
