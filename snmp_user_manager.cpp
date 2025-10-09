#include "config.h"

#include "snmp_user_manager.hpp"

#include "snmp_agent_serialize.hpp"
#include "snmp_agent_util.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#include <filesystem>
bool isSameUser = false;
namespace phosphor
{
namespace snmp
{
namespace user
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using namespace phosphor::network::snmp;

ConfManager::ConfManager(sdbusplus::bus_t& bus, const char* objPath) :
    details::CreateIface(bus, objPath,
                         details::CreateIface::action::defer_emit),
    dbusPersistentLocation(SNMP_USER_CONF_PERSIST_PATH), bus(bus),
    objectPath(objPath)
{}

std::string ConfManager::client(std::string userName, std::string password,
                                std::string encryption, std::string algorithm,
                                std::string readWritePermission)
{
    bool isValidPropertie = false;
    std::string existingUser = "newUser";
    // will throw exception if it is already configured.
    isValidPropertie =
        (userNameValidate(userName) && passwordValidate(password) &&
         encryptionValidate(encryption) && algorithmValidate(algorithm) &&
         ReadWritePermissionValidate(readWritePermission));
    if (!isValidPropertie)
    {
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("Community String Creation failled."),
            Argument::ARGUMENT_VALUE("Invalid Parameters."));
    }
    checkClientConfigured(userName, password, encryption, algorithm,
                          readWritePermission);
    std::filesystem::path objPath;
    if (isSameUser)
    {
        deleteSNMPClient(userName);
        objPath /= objectPath;
        objPath /= userName;

        auto client = std::make_unique<phosphor::snmp::user::UserManager>(
            bus, objPath.string().c_str(), *this, userName, password,
            encryption, algorithm, readWritePermission);
        // save the D-Bus object
        serialize(userName, *client, dbusPersistentLocation);
        this->clients.emplace(userName, std::move(client));
    }
    else
    {
        // create the D-Bus object
        objPath /= objectPath;
        objPath /= userName;
        auto client = std::make_unique<phosphor::snmp::user::UserManager>(
            bus, objPath.string().c_str(), *this, userName, password,
            encryption, algorithm, readWritePermission);
        // save the D-Bus object
        serialize(userName, *client, dbusPersistentLocation);
        this->clients.emplace(userName, std::move(client));
        lastClientId++;
        createSNMPv3User(userName, password, encryption, algorithm,
                         readWritePermission);
    }
    return objPath.string();
}

void ConfManager::checkClientConfigured(
    const std::string userName, const std::string password,
    const std::string encryption, const std::string algorithm,
    const std::string readWritePermission)
{
    isSameUser = false;

    for (const auto& val : clients)
    {
        if (val.second.get()->userName() == userName &&
            val.second.get()->password() == password &&
            val.second.get()->encryption() == encryption &&
            val.second.get()->algorithm() == algorithm &&
            val.second.get()->readWritePermission() == readWritePermission)
        {
            lg2::error("Client already exist");
            elog<InvalidArgument>(
                Argument::ARGUMENT_NAME("USERNAME"),
                Argument::ARGUMENT_VALUE("Client already exist."));
        }
        if (val.second.get()->userName() == userName)
        {
            sameClientId = val.second.get()->id;
            isSameUser = true;
        }
    }
}

void ConfManager::deleteSNMPClient(std::string id)
{
    constexpr std::string_view snmpUSMConfFile = "/var/lib/net-snmp/snmpd.conf";
    std::string snmpConfFile = "/etc/snmpd.conf";
    bool isUpdatedSnmpUSMConfFile;
    bool isUpdatedSnmpConfFile;
    auto it = clients.find(id);
    if (it == clients.end())
    {
        lg2::error("Unable to delete the snmp client: {ID}", "ID", id);
        return;
    }

    std::error_code ec;
    // remove the persistent file
    fs::path fileName = dbusPersistentLocation;
    fileName /= id;

    if (fs::exists(fileName))
    {
        if (!fs::remove(fileName, ec))
        {
            lg2::error("Unable to delete {FILE}: {EC}", "FILE", fileName, "EC",
                       ec.value());
        }
    }
    else
    {
        lg2::error("{FILE} doesn't exist", "FILE", fileName);
    }

    /* Delete the SNMPClient subscription if one exists */
    phosphor::network::snmp::deleteSNMPManager(id);

    isUpdatedSnmpUSMConfFile =
        phosphor::network::snmp::updateFile(std::string{snmpUSMConfFile}, id);
    isUpdatedSnmpConfFile =
        phosphor::network::snmp::updateFile(snmpConfFile, id);
    if (isUpdatedSnmpUSMConfFile || isUpdatedSnmpConfFile)
    {
        if (system("systemctl restart snmpd.service") == -1)
        {
            lg2::error("Restarting the snmpd.service Failed....");
        }
    }

    // remove the D-Bus Object.
    this->clients.erase(it);
}

void ConfManager::restoreClients()
{
    if (!fs::exists(dbusPersistentLocation) ||
        fs::is_empty(dbusPersistentLocation))
    {
        return;
    }

    for (auto& confFile :
         fs::recursive_directory_iterator(dbusPersistentLocation))
    {
        if (!fs::is_regular_file(confFile))
        {
            continue;
        }
        std::string userRef = confFile.path().filename().string();
        fs::path objPath = objectPath + "/" + userRef;
        auto manager =
            std::make_unique<UserManager>(bus, objPath.string().c_str(), *this);
        if (deserialize(confFile.path(), *manager))
        {
            manager->emit_object_added();
            this->clients.emplace(userRef, std::move(manager));
        }
    }
}
} // namespace user
} // namespace snmp
} // namespace phosphor
