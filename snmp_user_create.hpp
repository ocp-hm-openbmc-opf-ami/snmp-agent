#pragma once
#include "xyz/openbmc_project/Object/Delete/server.hpp"
#include "xyz/openbmc_project/Snmp/UserManager/server.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>
#include <string>

namespace phosphor
{
namespace snmp
{
namespace user
{

class ConfManager;

using Ifaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Snmp::server::UserManager,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

using Id = size_t;

/** @class UserManager
 *  @brief represents the snmp UserManager configuration
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.UserManager Dbus interface.
 */
class UserManager : public Ifaces
{
  public:
    UserManager() = delete;
    UserManager(const UserManager&) = delete;
    UserManager& operator=(const UserManager&) = delete;
    UserManager(UserManager&&) = delete;
    UserManager& operator=(UserManager&&) = delete;
    virtual ~UserManager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent D-bus Object.
     *  @param[in] address - IPaddress/Hostname.
     *  @param[in] port - network port.
     */
    UserManager(sdbusplus::bus_t& bus, const char* objPath, ConfManager& parent,
                const std::string userName, const std::string password,
                const std::string encryption, const std::string algorithm,
                const std::string readWritePermission);

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent D-bus Object.
     */
    UserManager(sdbusplus::bus_t& bus, const char* objPath,
                ConfManager& parent) :
        Ifaces(bus, objPath, Ifaces::action::defer_emit), parent(parent)
    {}

    /** @brief Update the address of the object.
     *
     *  @param[in] value - IP address
     *
     *  @return On success the updated IP address
     */
    std::string userName(std::string value) override;

    /** @brief Update the port
     *
     *  @param[in] value - port number
     *
     *  @return On success the updated port number
     */
    std::string password(std::string value) override;

    /** @brief Update the SNMP version of the object.
     *
     *  @param[in] value - SNMP version
     *
     *  @return On success the updated SNMP version
     */
    std::string encryption(std::string value) override;

    /** @brief Update the SNMP v3 user of the object.
     *
     *  @param[in] value - SNMP v3 username
     *
     *  @return On success the updated SNMP version
     */
    std::string algorithm(std::string value) override;

    /** @brief Update the SNMP v3 user's password of the object.
     *
     *  @param[in] value - SNMP v3 password
     *
     *  @return On success the updated V3 user password
     */
    std::string readWritePermission(std::string value) override;

    /** @brief Update the SNMP v3 readonlypermission of the object.
     *
     *  @param[in] value - SNMP v3 readonlypermission
     *
     *  @return On success the updated readonlypermission
     */
    // bool readonlypermission(bool permissionbyte) override;

    /** @brief Update the algorithm of the object.
     *
     *  @param[in] value - v3 algorithm
     *
     *  @return On success the updated V3 Algorithm
     */
    // std::string algorithm(std::string value) override;

    /** @brief Update the encryption of the object.
     *
     *  @param[in] value - encryption
     *
     *  @return On success the updated encryption
     */
    // std::string encryption(std::string value) override;

    using sdbusplus::xyz::openbmc_project::Snmp::server::UserManager::userName;

    using sdbusplus::xyz::openbmc_project::Snmp::server::UserManager::password;

    using sdbusplus::xyz::openbmc_project::Snmp::server::UserManager::
        encryption;

    using sdbusplus::xyz::openbmc_project::Snmp::server::UserManager::algorithm;
    using sdbusplus::xyz::openbmc_project::Snmp::server::UserManager::
        readWritePermission;

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    /** UserManager ID. */
    Id id;

  private:
    /** @brief Parent D-Bus Object. */
    ConfManager& parent;

    /** @brief Flag to indicate that the object is being initialized.
     *  Set to true during construction to prevent side effects
     *  (reConfigureSnmpUser, createSNMPv3User, serialize) from
     *  being triggered by property setters during initial object
     *  creation. Reset to false after construction completes so
     *  that subsequent property updates behave normally.
     */
    bool isInitialize = false;
};
} // namespace user
} // namespace snmp
} // namespace phosphor
