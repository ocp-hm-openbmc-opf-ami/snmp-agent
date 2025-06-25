/******************************************************************
 *
 * SNMP Agent
 * snmp-agent.cpp
 *
 * @brief dbus service for snmp-agent
 *
 * Author: Lucas Panayioto lucasp@ami.com
 *
 *****************************************************************/

#include "snmpAgent.hpp"

#include "netSnmpAmi.hpp"
#include "netSnmpAmiHandle.hpp"
#include "netSnmpExamples.hpp"
#include "netSnmpHostsTable.hpp"
#include "snmpModifyConf.hpp"
#include "snmpUtils.hpp"

// Dbus
#include "config.h"

#include <getopt.h>

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server/object.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// net-snmp
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <signal.h>

// D-Bus root for backup restore
constexpr auto snmpAgentRoot = "/xyz/openbmc_project/Snmp";

using namespace phosphor::logging;

using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

namespace fs = std::filesystem;

int main(int argc, char** argv)
{
    if (!std::filesystem::exists(SnmpTrapStatusFile))
    {
        std::ofstream file(SnmpTrapStatusFile, std::ios::out);
        if (file.is_open())
        {
            file << std::boolalpha << true << std::endl;
            file.close();
        }
        else
        {
            if (argc >= 1)
            {
                std::cerr << "Unable to open file" << SnmpTrapStatusFile << argc
                          << argv[0] << std::endl;
            }
        }
    }

    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    // Snmp Object Manager
    sdbusplus::server::manager_t objManager(*conn, "xyz.openbmc_project.Snmp");
    conn->request_name("xyz.openbmc_project.Snmp");

    // Snmp Utils Manager
    auto manager = std::make_unique<SnmpUtilsManager>(*conn, snmpAgentRoot);

    auto server = sdbusplus::asio::object_server(conn);

    auto ifaceSnmpUtils = server.add_interface(
        snmpAgentRoot, "xyz.openbmc_project.Snmp.SnmpUtils");
    registerSnmpUtilsDbus(ifaceSnmpUtils);

    auto ifaceSnmpdConf = server.add_interface(
        snmpAgentRoot, "xyz.openbmc_project.Snmp.SnmpdConf");
    registerSnmpdDbus(ifaceSnmpdConf);

    auto ifaceSnmpConf = server.add_interface(
        snmpAgentRoot, "xyz.openbmc_project.Snmp.SnmpConf");
    registerSnmpDbus(ifaceSnmpConf);

    // initialize_amiHandlers();
    auto eventHandler = std::async(std::launch::async, initialize_amiHandlers);
    io.run();
    eventHandler.wait();

    return -1;
}

int initialize_amiHandlers(void)
{
    int agentx_subagent =
        1;              /* change this if you want to be a SNMP master agent */
    int background = 0; /* change this if you want to run in the background */
    int syslog = 0;     /* change this if you want to use syslog */

    // long nstAgentSubagentObject = 2;
    // oid nstAgentSubagentObject_oid[] =
    //    { 1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 1, 2, 0 };

    /* print log errors to syslog or stderr */
    if (syslog)
        snmp_enable_calllog();
    else
        snmp_enable_stderrlog();

    /* we're an agentx subagent? */
    if (agentx_subagent)
    {
        /* make us a agentx client. */
        netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE,
                               1);
    }

    /* run in background, if requested */
    if (background && netsnmp_daemonize(1, !syslog))
        exit(1);

    /* initialize tcpip, if necessary */
    SOCK_STARTUP;

    /* initialize the agent library */
    init_agent("example-demon");

    /* initialize mib code here */

    /* mib code: init_nstAgentSubagentObject from nstAgentSubagentObject.C */
    // init_netSnmpExampleScalars();
    init_netSnmpHostsTable();
    init_netSnmpAMIScalars();
    init_netSnmpAmiSensorTable();
    init_netSnmpAmiDiscreteSensorTable();
    init_netSnmpAmiUserInfoTable();

    // init_nstAgentSubagentObject();
    /*
    netsnmp_register_long_instance("nstAgentSubagentObject",
                   nstAgentSubagentObject_oid,
                   OID_LENGTH(nstAgentSubagentObject_oid),
                   &nstAgentSubagentObject, NULL);
    */

    /* initialize vacm/usm access control  */
    if (!agentx_subagent)
    {
        init_vacm_vars();
        init_usmUser();
    }

    /* example-demon will be used to read example-demon.conf files. */
    init_snmp("example-demon");

    /* If we're going to be a snmp master agent, initial the ports */
    // if (!agentx_subagent)
    // init_master_agent();  /* open the port to listen on (defaults to udp:161)
    // */

    /* In case we recevie a request to stop (kill -TERM or kill -INT) */
    int keep_running = 1;
    // signal(SIGTERM, stop_server);
    // signal(SIGINT, stop_server);

    snmp_log(LOG_INFO, "example-demon is up and running.\n");

    /* your main loop here... */
    while (keep_running)
    {
        /* if you use select(), see snmp_select_info() in snmp_api(3) */
        /*     --- OR ---  */
        agent_check_and_process(1); /* 0 == don't block */
    }

    /* at shutdown time */
    snmp_shutdown("example-demon");
    SOCK_CLEANUP;

    return 0;
}
