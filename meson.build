project('snmp-agent',
        'cpp',
        version: '1.0',
	meson_version: '>=0.58.0',
        default_options: [
          'warning_level=3',
          'werror=true',
          'cpp_std=c++20',
          'buildtype=debugoptimized',
        ]
)

conf_data = configuration_data()


conf_header = configure_file(output: 'config.h',
    configuration: conf_data)


phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')



phosphor_logging_dep = dependency('phosphor-logging')
phosphor_snmp_dep = dependency('phosphor-snmp')
systemd_dep = dependency('systemd')

netsnmp_dep = dependency('netsnmp')

cpp = meson.get_compiler('cpp')

snmp_agent_dep = [
     phosphor_logging_dep,
     phosphor_snmp_dep,
     systemd_dep,
     phosphor_dbus_interfaces,
     sdbusplus,
     sdeventplus,
     netsnmp_dep,
]

snmp_agent_src = [
     'snmpAgent.cpp',
     'snmpAgent.hpp',
     'netSnmpExamples.cpp',
     'netSnmpExamples.hpp',
     'netSnmpHostsTable.cpp',
     'netSnmpHostsTable.hpp',
     'netSnmpControlSmtp.cpp',
     'netSnmpControlSmtp.hpp',
     'snmpUtils.hpp',
]

executable(
    'snmp-agent',
    snmp_agent_src,
    dependencies: [
    snmp_agent_dep,
    ],
    link_args: ['-lnetsnmpagent'],
    cpp_args: ['-DBOOST_ALL_NO_LIB', '-DBOOST_SYSTEM_NO_DEPRECATED', '-DBOOST_ERROR_CODE_HEADER_ONLY'],
    install: true,
)


