#include "config.h"

#include "snmp_conf_manager.hpp"

#include "snmpModifyConf.hpp"
#include "snmp_agent_serialize.hpp"
#include "snmp_agent_util.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#include <filesystem>
bool IssameClient = false;
namespace phosphor
{
namespace snmp
{
namespace communityStr
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace phosphor::network::snmp;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

ConfManager::ConfManager(sdbusplus::bus_t& bus, const char* objPath) :
    details::CreateIface(bus, objPath,
                         details::CreateIface::action::defer_emit),
    dbusPersistentLocation(SNMP_CONF_PERSIST_PATH), bus(bus),
    objectPath(objPath)
{}

std::string ConfManager::client(std::string communityString,
                                std::string readWritePermission,
                                std::string communityProfile)
{
    bool isValidPropertie = false;
    isValidPropertie = (communityStringValidation(communityString) &&
                        (communityStringPermission(readWritePermission) &&
                         communityStringProfile(communityProfile)));
    if (!isValidPropertie)
    {
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("Community String Creation failled."),
            Argument::ARGUMENT_VALUE("Invalid Parameters."));
    }
    // will throw exception if it is already configured.
    checkClientConfigured(communityString, readWritePermission,
                          communityProfile);

    std::filesystem::path objPath;
    if (IssameClient)
    {
        removeCommunityString(communityString);
        deleteSNMPClient(communityString);
        objPath /= objectPath;
        objPath /= communityString;

        auto client =
            std::make_unique<phosphor::snmp::communityStr::CommunityStrManager>(
                bus, objPath.string().c_str(), *this, communityString,
                readWritePermission, communityProfile);
        // save the D-Bus object
        serialize(communityString, *client, dbusPersistentLocation);
        this->clients.emplace(communityString, std::move(client));
    }
    else
    {
        // create the D-Bus object
        objPath /= objectPath;
        objPath /= communityString;
        auto client =
            std::make_unique<phosphor::snmp::communityStr::CommunityStrManager>(
                bus, objPath.string().c_str(), *this, communityString,
                readWritePermission, communityProfile);
        // save the D-Bus object
        serialize(communityString, *client, dbusPersistentLocation);
        this->clients.emplace(communityString, std::move(client));
        lastClientId++;
    }
    addCommunityString(readWritePermission, communityString, communityProfile);
    return objPath.string();
}

void ConfManager::checkClientConfigured(const std::string& communityString,
                                        const std::string& readWritePermission,
                                        const std::string& communityProfile)
{
    IssameClient = false;

    for (const auto& val : clients)
    {
        if (val.second.get()->communityString() == communityString &&
            val.second.get()->readWritePermission() == readWritePermission &&
            val.second.get()->communityProfile() == communityProfile)
        {
            lg2::error("Client already exist");
            elog<InvalidArgument>(
                Argument::ARGUMENT_NAME("COMMUNITYSTRING"),
                Argument::ARGUMENT_VALUE("Client already exist."));
        }
        if (val.second.get()->communityString() == communityString)
        {
            sameClientId = val.second.get()->id;
            IssameClient = true;
        }
    }
}

void ConfManager::deleteSNMPClient(std::string id)
{
    std::string snmpdConfExtFilepath = "/etc/snmp/snmpd.conf.d/snmpd.conf";
    bool isUpdated;

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

    isUpdated = phosphor::network::snmp::updateFile(snmpdConfExtFilepath, id);

    if (isUpdated)
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

        std::string communityRef = confFile.path().filename().string();
        fs::path objPath = objectPath + "/" + communityRef;
        auto manager =
            std::make_unique<phosphor::snmp::communityStr::CommunityStrManager>(
                bus, objPath.string().c_str(), *this);
        if (deserialize(confFile.path(), *manager))
        {
            manager->emit_object_added();
            this->clients.emplace(communityRef, std::move(manager));
        }
    }
}

void ConfManager::delete_dbus_object(const char* service,
                                     const char* object_path)
{
    auto bus = sdbusplus::bus::new_default();

    // Create a method call to delete the object
    auto msg = bus.new_method_call(
        service,                             // Destination (bus name)
        object_path,                         // Object path
        "xyz.openbmc_project.Object.Delete", // Interface name
        "Delete"                             // Method name
    );

    try
    {
        // Send the message and wait for a reply
        bus.call(msg);
        std::cout << "Object deleted successfully." << std::endl;
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        std::cerr << "Error in sending message: " << e.what() << std::endl;
    }
}

} // namespace communityStr
} // namespace snmp
} // namespace phosphor
