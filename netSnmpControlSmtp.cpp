#include "netSnmpControlSmtp.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message/types.hpp>
#include <iostream>

static constexpr const char* smtpclient = "xyz.openbmc_project.mail";
static constexpr const char* smtpObj = "/xyz/openbmc_project/mail/alert";
static constexpr const char* smtpPriIntf = "xyz.openbmc_project.mail.alert.primary";
static constexpr const char* smtpSecIntf = "xyz.openbmc_project.mail.alert.secondary";


using DbusUserPropVariant = std::variant<std::vector<std::string>, std::string, bool>;

void setDbusProperty(const std::string& service,
                     const std::string& objPath, const std::string& interface,
                     const std::string& property,
                     DbusUserPropVariant& value)
{
     auto bus = sdbusplus::bus::new_default();
    try
    {
        auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          "org.freedesktop.DBus.Properties",
                                          "Set");
        method.append(interface, property, value);
        bus.call(method);
    }
    catch (const sdbusplus::exception_t& e)
    {
	std::cerr << "Error in setDbusproperty \n";
    }

}

void getDbusProperty(const std::string& service,
                                   const std::string& objPath,
                                   const std::string& interface,
                                   const std::string& property,
                                   DbusUserPropVariant& value)
{
     auto bus = sdbusplus::bus::new_default();
    try
    {
        auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          "org.freedesktop.DBus.Properties",
                                          "Get");

        method.append(interface, property);

        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (const sdbusplus::exception_t& e)
    {
        std::cerr << "Fail to getDbusProperty" << std::endl;
    }

}


void
init_netSnmpControlSmtpScalars(void)
{
    const oid amiSnmpSMTPPriStatus_oid[] = {1,3,6,1,4,1,8072,3,1,1};
    const oid amiSnmpSMTPSecStatus_oid[] = {1,3,6,1,4,1,8072,3,1,2};

    DEBUGMSGTL(("netSnmpControlSnmpScalars", "Initializing\n"));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration("amiSnmpSMTPPriStatus", handle_amiSnmpSMTPPriStatus,
                               amiSnmpSMTPPriStatus_oid, OID_LENGTH(amiSnmpSMTPPriStatus_oid),
                               HANDLER_CAN_RWRITE
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("amiSnmpSMTPSecStatus", handle_amiSnmpSMTPSecStatus,
                               amiSnmpSMTPSecStatus_oid, OID_LENGTH(amiSnmpSMTPSecStatus_oid),
                               HANDLER_CAN_RWRITE
        ));

}

int handle_amiSnmpSMTPPriStatus(netsnmp_mib_handler *handler,
                               netsnmp_handler_registration *reginfo,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests)
{
    int ret;
    std::tuple<bool, std::string, uint16_t, std::string> smtpcfg;
    std::vector<std::string> rec;
    DbusUserPropVariant variant;

    std::cout << "handle_amiSnmpSMTPPriStatus" << std::endl;
    

    std::ofstream fpchassis;
    fpchassis.open(tempChassisFilepath,std::ios_base::app);
    fpchassis << "handle ami Snmp  SMTP status "  << std::endl;
    fpchassis.close();
    int status = 1;

    if(0)
    {
        reginfo = reginfo;
        handler = handler;
    }
    std::cout << "reqinfo->mode " << reqinfo->mode << std::endl;

    switch(reqinfo->mode) {
        case MODE_GET:
            getDbusProperty(smtpclient, smtpObj, smtpPriIntf, "Enable", variant);
            status = std::get<bool>(variant);
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,(u_char *)&status, sizeof(int));
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE GET " << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_RESERVE1:
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET RESERVE1 " << std::endl;
            fpchassis.close();
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET RESERVE2 " << std::endl;
            fpchassis.close();
            if (/* XXX if malloc, or whatever, failed: */0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET FREE " << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_ACTION:
            status = *requests->requestvb->val.integer;
            if(status > 1)
            {
                return SNMP_ERR_BADVALUE;
            }
            variant = (status != 0);
            setDbusProperty(smtpclient, smtpObj, smtpPriIntf, "Enable", variant);                    
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (u_char *)&status, sizeof(status));
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET ACTION " << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_COMMIT:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET COMMIT" << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_UNDO:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET UNDO " << std::endl;
            fpchassis.close();
            break;

        default:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status DEFAULT " << std::endl;
            fpchassis.close();
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_amiSnmp_SMTP_status\n", reqinfo->mode );
            std::cout << "no mode" << std::endl;
            return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOERROR;
}


int handle_amiSnmpSMTPSecStatus(netsnmp_mib_handler *handler,
                               netsnmp_handler_registration *reginfo,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests)
{
    int ret;
    std::tuple<bool, std::string, uint16_t, std::string> smtpcfg;
    std::vector<std::string> rec;
    DbusUserPropVariant variant;
    std::cout << "handle_amiSnmpSMTPSecStatus" << std::endl;
    auto bus = sdbusplus::bus::new_default();
    

    std::ofstream fpchassis;
    fpchassis.open(tempChassisFilepath,std::ios_base::app);
    fpchassis << "handle ami Snmp  SMTP status "  << std::endl;
    fpchassis.close();

    int status;

    if(0)
    {
       reginfo = reginfo;
       handler = handler;
    }
    std::cout << "reqinfo->mode " << reqinfo->mode << std::endl;

    switch(reqinfo->mode) {
        case MODE_GET:
            getDbusProperty(smtpclient, smtpObj, smtpSecIntf, "Enable", variant);
            status = std::get<bool>(variant);
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                                 (u_char *)&status, sizeof(int));
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE GET " << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_RESERVE1:
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET RESERVE1 " << std::endl;
            fpchassis.close();
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET RESERVE2 " << std::endl;
            fpchassis.close();
            if (/* XXX if malloc, or whatever, failed: */0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET FREE " << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_ACTION:
            status = *requests->requestvb->val.integer;
            if(status > 1)
            {
                return SNMP_ERR_BADVALUE;
            }
            variant = (status != 0);
            setDbusProperty(smtpclient, smtpObj, smtpSecIntf, "Enable", variant);
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (u_char *)&status, sizeof(status));
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET ACTION " << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_COMMIT:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET COMMIT" << std::endl;
            fpchassis.close();
            break;

        case MODE_SET_UNDO:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status MODE SET UNDO " << std::endl;
            fpchassis.close();
            break;

        default:
            fpchassis.open(tempChassisFilepath,std::ios_base::app);
            fpchassis << "Handle ami snmp SMTP status DEFAULT " << std::endl;
            fpchassis.close();
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_amiSnmp_SMTP_status\n", reqinfo->mode );
            std::cout << "no mode" << std::endl;
            return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOERROR;
}

