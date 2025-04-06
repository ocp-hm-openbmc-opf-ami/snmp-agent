#include "netSnmpAmi.hpp"

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

static constexpr const char* acdBusName = "com.ami.ami_acd";
static constexpr const char* acdObjPath =  "/com/ami/ami_acd";
static constexpr const char* acdIntf = "com.ami.ami_acd.acdInterface";
std::string acd_Trigger;

using DbusUserPropVariant = std::variant<std::vector<std::string>, std::string, bool>;


template<typename T, typename... Args>
auto dbus_call(const std::string& service, const std::string& path,
               const std::string& interface, const std::string& method, Args&&... args)
{
    auto bus = sdbusplus::bus::new_default();
    auto msg = bus.new_method_call(service.c_str(), path.c_str(),
                                   interface.c_str(), method.c_str());

    // Append arguments to the D-Bus method call
    (msg.append(std::forward<Args>(args)), ...);

    // Call the method and get the response
    T response;
    try
    {
        auto reply = bus.call(msg);
        reply.read(response);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        std::cerr << "D-Bus call error: " << e.what() << '\n';
        throw;
    }
    return response;
}

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
init_netSnmpAMIScalars(void)
{
    const oid amiSnmpSMTPPriStatus_oid[] = {1,3,6,1,4,1,8072,3,1,1};
    const oid amiSnmpSMTPSecStatus_oid[] = {1,3,6,1,4,1,8072,3,1,2};
    const oid amiACD_DataArea_oid[] = {1,3,6,1,4,1,8072,3,2,1};
    const oid amiACD_Trigger_oid[] = {1,3,6,1,4,1,8072,3,2,2};

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

    netsnmp_register_scalar(
        netsnmp_create_handler_registration("amiACD_DataArea", handle_amiACD_DataArea,
                               amiACD_DataArea_oid, OID_LENGTH(amiACD_DataArea_oid),
                               HANDLER_CAN_RWRITE
        ));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration("amiACD_Trigger", handle_amiACD_Trigger,
                               amiACD_Trigger_oid, OID_LENGTH(amiACD_Trigger_oid),
                               HANDLER_CAN_RWRITE
        ));


}


int handle_amiACD_DataArea(netsnmp_mib_handler *handler,
                               netsnmp_handler_registration *reginfo,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests)
{

    int ret = 0;
    uint16_t dataArea = 0;
    std::cout << "reqinfo->mode " << reqinfo->mode<< reginfo->modes << handler->flags << std::endl;

    switch(reqinfo->mode) {
        case MODE_GET:
            try
            {
                dataArea = dbus_call<uint16_t>(acdBusName, acdObjPath, acdIntf, "Get_DataArea");
            }
            catch (const std::exception& e)
            {
                dataArea = 0;
                std::cerr << "Error calling D-Bus method: " << e.what() << '\n';
            }
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char *)&dataArea, sizeof(dataArea));
            break;

        case MODE_SET_RESERVE1:
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            if (/* XXX if malloc, or whatever, failed: */0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            break;

        case MODE_SET_ACTION:
            dataArea =  *requests->requestvb->val.integer;

            try
            {
                std::string setDataAreaResponse = dbus_call<std::string>(acdBusName, acdObjPath, acdIntf, "Set_DataArea", dataArea);
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error calling D-Bus method: " << e.what() << '\n';
                return SNMP_ERR_GENERR;
            }

            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char *)&dataArea, sizeof(dataArea));
            break;

        case MODE_SET_COMMIT:
            break;

        case MODE_SET_UNDO:
            break;

        default:
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_amiACD_dataArea\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOERROR;
}

int handle_amiACD_Trigger(netsnmp_mib_handler *handler,
                               netsnmp_handler_registration *reginfo,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests)
{
    int ret = 0;
    std::string action;
    std::cout << "reqinfo->mode " << reqinfo->mode<< reginfo->modes << handler->flags << std::endl;

    switch(reqinfo->mode) {
        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR , (const u_char*)acd_Trigger.c_str(), acd_Trigger.size());
            break;

        case MODE_SET_RESERVE1:
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            if (/* XXX if malloc, or whatever, failed: */0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            break;

        case MODE_SET_ACTION:

            action = (reinterpret_cast<char*>(requests->requestvb->val.string));
            if(action != "trigger")
            {
                return SNMP_ERR_BADVALUE;               
           }
            try
            {
                acd_Trigger = dbus_call<std::string>(acdBusName, acdObjPath, acdIntf, "ACD_trigger");
            }
            catch (const std::exception& e)
            {
                acd_Trigger = "";
                std::cerr << "Error calling D-Bus method: " << e.what() << '\n';
                return SNMP_ERR_GENERR;
            }
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR , (const u_char*)acd_Trigger.c_str(), acd_Trigger.size());
           
            break;


        case MODE_SET_COMMIT:
            break;

        case MODE_SET_UNDO:
            break;


        default:
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_amiACD_Trigger\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOERROR;
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
    

    int status = 1;

    std::cout << "reqinfo->mode " << reqinfo->mode<< reginfo->modes << handler->flags << std::endl;

    switch(reqinfo->mode) {
        case MODE_GET:
            getDbusProperty(smtpclient, smtpObj, smtpPriIntf, "Enable", variant);
            status = std::get<bool>(variant);
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,(u_char *)&status, sizeof(int));
            break;

        case MODE_SET_RESERVE1:
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            if (/* XXX if malloc, or whatever, failed: */0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
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
            break;

        case MODE_SET_COMMIT:
            break;

        case MODE_SET_UNDO:
            break;

        default:
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
    


    int status;

    std::cout << "reqinfo->mode " << reqinfo->mode << reginfo->modes<< handler->flags <<std::endl;

    switch(reqinfo->mode) {
        case MODE_GET:
            getDbusProperty(smtpclient, smtpObj, smtpSecIntf, "Enable", variant);
            status = std::get<bool>(variant);
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                                 (u_char *)&status, sizeof(int));
            break;

        case MODE_SET_RESERVE1:
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            if (/* XXX if malloc, or whatever, failed: */0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
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
            break;

        case MODE_SET_COMMIT:
            break;

        case MODE_SET_UNDO:
            break;

        default:
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_amiSnmp_SMTP_status\n", reqinfo->mode );
            std::cout << "no mode" << std::endl;
            return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOERROR;
}

