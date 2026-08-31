// stubs.cpp — lightweight stub implementations for symbols required by the
// test binary that originate from production modules not compiled into the
// test target.
//
// getDbusProperty is declared in netSnmpAmiHandle.hpp and called only from
// userNameValidate() and communityStringProfile().  Those two functions are
// excluded from the test scope (live D-Bus required).  All other tested
// validators never call getDbusProperty.
//
// Notification::sendTrap() is the non-virtual entry point in phosphor-snmp's
// Notification base class.  It would normally be linked from libsnmp.so;
// we provide a no-op stub so the test binary links without that library.

#include "netSnmpAmiHandle.hpp"
#include "snmp_notification.hpp"

// Stub: returns true so that userNameValidate's enableStatus check passes.
// Tests that need userNameValidate to fail use a non-existent username so
// that the /etc/passwd lookup fails instead.
dbusPropVariant getDbusProperty(
    const std::string& /*service*/, const std::string& /*objPath*/,
    const std::string& /*interface*/, const std::string& /*property*/)
{
    return true;
}

// Stub: Notification::sendTrap() — no-op; snmpUtils functions that call
// sendTrap<OBMCErrorNotification>() are not exercised by unit tests.
namespace phosphor
{
namespace network
{
namespace snmp
{
void Notification::sendTrap() {}
} // namespace snmp
} // namespace network
} // namespace phosphor
