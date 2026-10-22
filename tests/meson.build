gtest_dep = dependency('gtest', main: false, required: false)
gmock_dep = dependency('gmock', required: false)

if not gtest_dep.found() or not gmock_dep.found()
    cmake = import('cmake')
    opt_var = cmake.subproject_options()
    opt_var.add_cmake_defines({'CMAKE_CXX_FLAGS': '-Wno-pedantic'})
    opt_var.set_override_option('warning_level', '3')
    opt_var.set_override_option('werror', 'true')

    gtest_proj = cmake.subproject('gtest', options: opt_var, required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
            ],
        )
        gmock_dep = gtest_proj.dependency('gmock')
    else
        gtest_proj = subproject('gtest')
        gtest_dep = gtest_proj.get_variable('gtest_dep')
        gmock_dep = gtest_proj.get_variable('gmock_dep')
    endif
endif

test_deps = [
    gtest_dep,
    gmock_dep,
    netsnmp_dep,
    netsnmp_agent_dep,
    netsnmp_mibs_dep,
    netsnmp_helpers_dep,
    phosphor_logging_dep,
    phosphor_dbus_interfaces,
    sdbusplus,
    sdeventplus,
    openssl_dep,
]

# Production sources compiled into the test binary.
# Only modules whose functions are directly exercised by the tests are
# All production .cpp files that can be compiled into the test binary.
# Matches the production snmp_agent_src list in the root meson.build.
# Excluded:
#   snmp_agent_main.cpp  — only contains main(); zero testable functions;
#                          adding it only contributes uncovered lines
#   snmpAgent.cpp        — NOT in the production build (orphaned file);
#                          also has conflicting initialize_amiHandlers
#                          declaration vs netSnmpAmiHandle.hpp
#   user_mgmt.cpp        — IPMI-specific project, not in production build;
#                          requires apphandler.hpp / ipmid/types.hpp
# D-Bus calls in the included files are handled by:
#   - stubs.cpp provides dbusPropVariant getDbusProperty(4-param stub)
#     which wins over netSnmpAmiHandle.cpp's real definition via
#     --allow-multiple-definition (stubs.cpp is listed before production_sources)
#   - netSnmpAmi.cpp's void getDbusProperty(5-param) is a distinct overload;
#     its real body is compiled in but never called by any test
production_sources = [
    '../Encryption.cpp',
    '../snmpModifyConf.cpp',
    '../snmp_agent_util.cpp',
    '../netSnmpAmi.cpp',
    '../netSnmpAmiHandle.cpp',
    '../netSnmpExamples.cpp',
    '../netSnmpHostsTable.cpp',
    '../snmp_agent_client.cpp',
    '../snmp_agent_serialize.cpp',
    '../snmp_conf_manager.cpp',
    '../snmp_user_create.cpp',
    '../snmp_user_manager.cpp',
    '../snmpUtils.cpp',
]

test_exe = executable(
    'test_snmp_agent',
    [
        'test_main.cpp',
        'test_encryption.cpp',
        'test_snmp_agent_util.cpp',
        'test_snmpModifyConf.cpp',
        'test_snmp_utils_manager.cpp',
        'test_snmp_objects.cpp',
        'test_netsnmp_handler.cpp',
        'test_netsnmp_ami.cpp',
        'test_netsnmp_examples.cpp',
        'test_netsnmp_hosts.cpp',
        'stubs.cpp',
    ] + production_sources,
    include_directories: include_directories('..'),
    dependencies: test_deps,
    link_args: [
        '-lcrypto',
        '-lstdc++fs',
        '-lnetsnmpagent',
        '-Wl,--allow-multiple-definition',
        '--coverage',
    ],
    cpp_args: [
        '-DBOOST_ALL_NO_LIB',
        '-DBOOST_SYSTEM_NO_DEPRECATED',
        '-DBOOST_ERROR_CODE_HEADER_ONLY',
        '-DSNMP_AGENT_TESTS_BUILD',
        '--coverage',
    ],
)

test('unit_test_snmp_agent', test_exe)
