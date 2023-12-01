/*****************************************************************
 *
 * Snmp Agent
 * snmpAgent.hpp
 *
 * @brief dbus service for SNMP Agent
 *
 * Author: Lucas Panayioto lucasp@ami.com
 *
 *****************************************************************/



#include <boost/process/child.hpp>
#include <boost/process/io.hpp>


//Error Logging
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <getopt.h>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>


extern void init_usmUser(void);
extern void init_vacm_vars(void);
