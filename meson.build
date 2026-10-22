project('snmp-agent',
        'cpp',
        version: '1.0',
	meson_version: '>=1.1.1',
        default_options: [
          'warning_level=3',
          'werror=true',
          'cpp_std=c++23',
          'buildtype=debugoptimized',
        ]
)

if get_option('tests').enabled()
    add_project_arguments('-Wno-error=format', language: 'cpp')
endif

conf_data = configuration_data()
conf_data.set_quoted('BUSNAME_NETWORK_SNMP', 'xyz.openbmc_project.Snmp.Conf')
conf_data.set_quoted(
    'OBJ_NETWORK_SNMP',
    '/xyz/openbmc_project/snmp/CommunityStrManager',
)
conf_data.set_quoted(
    'OBJ_NETWORK_SNMP_USER',
    '/xyz/openbmc_project/snmp/UserManager',
)
conf_data.set_quoted(
    'OBJ_NETWORK_SNMP_UTILS',
    '/xyz/openbmc_project/snmp/SnmpUtils',
)
conf_data.set_quoted(
    'SNMP_CONF_PERSIST_PATH',
    '/var/lib/snmp-agent/managers/',
)
conf_data.set_quoted(
    'SNMP_USER_CONF_PERSIST_PATH',
    '/var/lib/snmp-agent/userManagers/',
)
conf_data.set('CLASS_VERSION', 1)

conf_header = configure_file(output: 'config.h',
    configuration: conf_data)

if get_option('tests').enabled()
    sdbusplus = subproject('sdbusplus').get_variable('sdbusplus_dep')
    meson.override_dependency('sdbusplus',sdbusplus)
    phosphor_dbus_interfaces= dependency('phosphor-dbus-interfaces-ami')
    phosphor_logging_dep = subproject('phosphor-logging').get_variable('phosphor_logging_dep')
else
    sdbusplus = dependency('sdbusplus')
    phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
    phosphor_logging_dep = dependency('phosphor-logging')
endif

sdeventplus = dependency('sdeventplus')
phosphor_snmp_dep = dependency('phosphor-snmp')
systemd_dep = dependency('systemd')

netsnmp_dep = dependency('netsnmp')
if get_option('tests').enabled()
    _cc = meson.get_compiler('cpp')
    netsnmp_agent_dep = _cc.find_library('netsnmpagent', required: true)
    netsnmp_mibs_dep = _cc.find_library('netsnmpmibs', required: true)
    netsnmp_helpers_dep = _cc.find_library('netsnmphelpers', required: true)
endif
openssl_dep = dependency('openssl')

cpp = meson.get_compiler('cpp')

snmp_agent_dep = [
     phosphor_logging_dep,
     phosphor_snmp_dep,
     systemd_dep,
     phosphor_dbus_interfaces,
     sdbusplus,
     sdeventplus,
     netsnmp_dep,
     openssl_dep,
]

snmp_agent_src = [
     'snmp_agent_main.cpp',
     'snmp_conf_manager.cpp',
     'snmp_conf_manager.hpp',
     'snmp_agent_client.cpp',
     'snmp_agent_client.hpp',
     'snmp_agent_serialize.cpp',
     'snmp_agent_serialize.hpp',
     'snmp_user_manager.cpp',
     'snmp_user_manager.hpp',
     'snmp_user_create.cpp',
     'snmp_user_create.hpp',
     'snmpModifyConf.hpp',
     'snmpModifyConf.cpp',
     'snmpUtils.hpp',
     'snmpUtils.cpp',
     'snmp_agent_util.hpp',
     'snmp_agent_util.cpp',
     'netSnmpAmiHandle.cpp',
     'netSnmpAmiHandle.hpp',
     'netSnmpExamples.cpp',
     'netSnmpExamples.hpp',
     'netSnmpAmi.cpp',
     'netSnmpAmi.hpp',
     'netSnmpHostsTable.hpp',
     'netSnmpHostsTable.cpp',
     'Encryption.hpp',
     'Encryption.cpp'
]

extra_link_args = []
if get_option('tests').enabled()
    extra_link_args += ['-Wl,--allow-multiple-definition']
endif

executable(
    'snmp-agent',
    snmp_agent_src,
    dependencies: [
    snmp_agent_dep,
    ],
    link_args: ['-lnetsnmpagent'] + extra_link_args,
    cpp_args: ['-DBOOST_ALL_NO_LIB', '-DBOOST_SYSTEM_NO_DEPRECATED', '-DBOOST_ERROR_CODE_HEADER_ONLY'],
    install: true,
)

if get_option('tests').enabled()
    subdir('tests')
endif



