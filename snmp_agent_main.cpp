#include "config.h"

#include "netSnmpAmi.hpp"
#include "netSnmpAmiHandle.hpp"
#include "netSnmpExamples.hpp"
#include "netSnmpHostsTable.hpp"
#include "snmpUtils.hpp"
#include "snmp_conf_manager.hpp"
#include "snmp_user_manager.hpp"

#include <net-snmp/library/tools.h>
#include <net-snmp/net-snmp-config.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

#include <future>
#include <memory>
/* Need a custom deleter for freeing up sd_event */
std::string SnmpTrapStatusCreation = "/etc/snmp/SnmpTrapStatus";
struct EventDeleter
{
    void operator()(sd_event* event) const
    {
        sd_event_unref(event);
    }
};

using EventPtr = std::unique_ptr<sd_event, EventDeleter>;

int main(int /*argc*/, char** /*argv[]*/)
{
    if (!std::filesystem::exists(SnmpTrapStatusCreation))
    {
        std::ofstream file(SnmpTrapStatusCreation, std::ios::out);
        if (file.is_open())
        {
            file << std::boolalpha << true << std::endl;
            file.close();
        }
    }
    try
    {
        auto bus = sdbusplus::bus::new_default();

        sd_event* event = nullptr;
        auto r = sd_event_default(&event);
        if (r < 0)
        {
            lg2::error("Error creating a default sd_event handler: {RC}", "RC",
                       r);
            return r;
        }

        EventPtr eventPtr{event};
        event = nullptr;

        // Attach the bus to sd_event to service user requests
        bus.attach_event(eventPtr.get(), SD_EVENT_PRIORITY_NORMAL);

        // Add sdbusplus Object Manager for the 'root' path of the snmp.
        sdbusplus::server::manager_t objManager(bus, OBJ_NETWORK_SNMP);
        sdbusplus::server::manager_t objManager1(
            bus, "/xyz/openbmc_project/snmp/UserManager");
        sdbusplus::server::manager_t objManager2(
            bus, "/xyz/openbmc_project/snmp/SnmpUtils");
        bus.request_name(BUSNAME_NETWORK_SNMP);

        auto manager =
            std::make_unique<phosphor::snmp::communityStr::ConfManager>(
                bus, OBJ_NETWORK_SNMP);
        auto manager_1 = std::make_unique<phosphor::snmp::user::ConfManager>(
            bus, OBJ_NETWORK_SNMP_USER);
        auto manager_2 =
            std::make_unique<phosphor::snmp::SnmpUtils::SnmpUtilsManager>(
                bus, OBJ_NETWORK_SNMP_UTILS);

        manager->restoreClients();
        manager_1->restoreClients();

        auto eventHandler =
            std::async(std::launch::async, initialize_amiHandlers);
        sd_event_loop(eventPtr.get());
        eventHandler.wait();
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error creating default bus: " << e.what() << std::endl;
        return 0;
    }
}
