#pragma once

#include "snmp_user_create.hpp"

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Snmp/UserManager/Create/server.hpp>

#include <string>

namespace phosphor
{
namespace snmp
{
namespace user
{

using ClientList = std::map<std::string, std::unique_ptr<UserManager>>;
namespace fs = std::filesystem;

namespace details
{

using CreateIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Snmp::UserManager::server::Create>;

} // namespace details

class TestSNMPConfManager;
/** @class Manager
 *  @brief OpenBMC SNMP config  implementation.
 */
class ConfManager : public details::CreateIface
{
  public:
    ConfManager() = delete;
    ConfManager(const ConfManager&) = delete;
    ConfManager& operator=(const ConfManager&) = delete;
    ConfManager(ConfManager&&) = delete;
    ConfManager& operator=(ConfManager&&) = delete;
    virtual ~ConfManager() = default;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     */
    ConfManager(sdbusplus::bus_t& bus, const char* objPath);

    /** @brief Function to create snmp manager details D-Bus object.
     *  @param[in] address- IP address/Hostname.
     *  @param[in] port - network port.
     *  @returns D-Bus object path
     */
    std::string client(std::string userName, std::string password,
                       std::string encryption, std::string algorithm,
                       std::string readWritePermission);

    /* @brief delete the D-Bus object of the given ID.
     * @param[in] id - client identifier.
     */
    void deleteSNMPClient(std::string id);

    /** @brief Construct manager/client D-Bus objects from their persisted
     *         representations.
     */
    void restoreClients();

    /** @brief Check if client is already configured or not.
     *
     *  @param[in] address - SNMP manager address.
     *  @param[in] port -    SNMP manager port.
     *
     *  @return throw exception if client is already configured.
     */
    void checkClientConfigured(
        const std::string userName, const std::string password,
        const std::string encryption, const std::string algorithm,
        const std::string readWritePermission);

    /** @brief location of the persisted D-Bus object.*/
    fs::path dbusPersistentLocation;

  private:
    /** @brief sdbusplus DBus bus object. */
    sdbusplus::bus_t& bus;

    /** @brief Path of Object. */
    std::string objectPath;

    /** @brief map of SNMP Client dbus objects and their ID */
    ClientList clients;

    /** @brief Id of the SameClient SNMP manager entry */
    Id sameClientId = 0;

    /** @brief Id of the last SNMP manager entry */
    Id lastClientId = 1;

    friend class TestSNMPConfManager;
};
} // namespace user
} // namespace snmp
} // namespace phosphor
