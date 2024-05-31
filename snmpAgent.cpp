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
#include "netSnmpControlSmtp.hpp"
#include "netSnmpExamples.hpp"
#include "netSnmpHostsTable.hpp"
#include "snmpModifyConf.hpp"
#include "snmpUtils.hpp"

//Dbus
#include "config.h"
#include <boost/asio/io_context.hpp>
#include <getopt.h>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Snmp/SnmpAgent/server.hpp>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// net-snmp
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
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

using IfcBase = sdbusplus::xyz::openbmc_project::Snmp::server::SnmpAgent;

namespace fs = std::filesystem;

class SnmpAgentImp : IfcBase
{
    public:
        /* Define all of the basic class operations:
         *     Not allowed:
         *         - Default constructor to avoid nullptrs.
         *         - Copy operations due to internal unique_ptr.
         *         - Move operations due to 'this' being registered as the
         *           'context' with sdbus.
         *     Allowed:
         *         - Destructor.
         */
        SnmpAgentImp() = delete;
        SnmpAgentImp(const SnmpAgentImp&) = delete;
        SnmpAgentImp& operator=(const SnmpAgentImp&) = delete;
        SnmpAgentImp(SnmpAgentImp&&) = delete;
        SnmpAgentImp& operator=(SnmpAgentImp&&) = delete;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         */
        SnmpAgentImp(sdbusplus::bus_t& bus, const char* path) :
            IfcBase(bus, path)
        {

	}

        /** Method: Snmp Agent file
         *  @brief Implementation Create Backup file
         *  @param[in] fileName - name of backup file
         */
        std::string createSnmpAgent( std::string snmpAgent)  override
        {
	    int retval;

	    std::ofstream fpchassis;
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "Create Snmp Agent " << std::endl;
	    fpchassis.close();
	    
	    /*
	    //retval = snmpdemo();
	    init_amiSnmpScalars();
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "Create SNMP simple App: " << retval << std::endl;
	    fpchassis.close();
	    */

	    
	    
	    retval = exampleDeamon();
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "Create SNMP example Deamon: " << retval << std::endl;
	    fpchassis.close();
	    	    

	    
	    return std::string{"test"};
	    return snmpAgent;
	}
  
        /** Method: Snmp Agent file
	 *  @brief Implementation Create Backup file
         *  @param[in] fileName - name of backup file
         */
        std::string getSnmpAgent(void) override
        {

	  return std::string{"test"};
	}
  
private:
  
  static int handle_amiSnmpInteger(netsnmp_mib_handler *handler,
			    netsnmp_handler_registration *reginfo,
			    netsnmp_agent_request_info   *reqinfo,
			    netsnmp_request_info         *requests)
  {
       int ret;
       /* We are never called for a GETNEXT if it's registered as a
	  "instance", as it's "magically" handled for us.  */

       if(0)
	 {
	   handler = handler;
	   reginfo = reginfo;
	 }
       
       /* a instance handler also only hands us one request at a time, so
	  we don't need to loop over a list of requests; we'll only get one. */
       
       switch(reqinfo->mode) {
	 
       case MODE_GET:
	 //snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
	 //			  /* XXX: a pointer to the scalar's data */,
	 //			  /* XXX: the length of the data in bytes */);
	 break;
        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;
	    
       case MODE_SET_RESERVE2:
            /* XXX malloc "undo" storage buffer */
	  //if (/* XXX if malloc, or whatever, failed: */) {
	  // netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
	  //}
            break;

        case MODE_SET_FREE:
            /* XXX: free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            break;
       case MODE_SET_ACTION:
            /* XXX: perform the value change here */
            //if (/* XXX: error? */) {
	 //  netsnmp_set_request_error(reqinfo, requests, /* some error */);
	 // }
            break;

        case MODE_SET_COMMIT:
            /* XXX: delete temporary storage */
            //if (/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
	  //  netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_COMMITFAILED);
	  //}
            break;

        case MODE_SET_UNDO:
            /* XXX: UNDO and return to previous value for the object */
            //if (/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
	  //   netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_UNDOFAILED);
	  //}
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_amiSnmpInteger\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }
       
    return SNMP_ERR_NOERROR;
	 
  }


    /** Initializes the amiSnmpScalars module */
  void init_amiSnmpScalars(void)
  {
    const oid amiSnmpInteger_oid[] = { 1,3,6,1,4,1,8072,2,1,1 };
    
    DEBUGMSGTL(("amiSnmpScalars", "Initializing\n"));
    
    netsnmp_register_scalar(
	netsnmp_create_handler_registration("amiSnmpInteger", handle_amiSnmpInteger,
					    amiSnmpInteger_oid, OID_LENGTH(amiSnmpInteger_oid),
					    HANDLER_CAN_RWRITE
					    ));
  }


  int snmpdemo(void)
        {
	    netsnmp_session session, *ss;
	    netsnmp_pdu *pdu;
	    netsnmp_pdu *response;
	    
	    oid anOID[MAX_OID_LEN];
	    size_t anOID_len;
	    
	    netsnmp_variable_list *vars;
	    int status;
	    int count=1;

	    std::ofstream fpchassis;
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Start" << std::endl;
	    fpchassis.close();
	    
	    /*
	     * Initialize the SNMP library
	     */
	    init_snmp("snmpdemoapp");

	    
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo App initiated" << std::endl;
	    fpchassis.close();
	    
	    /*
	     * Initialize a "session" that defines who we're going to talk to
	     */
	    snmp_sess_init( &session );                   /* set up defaults */
	    session.peername = strdup("localhost");



	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo intiated Session" << std::endl;
	    fpchassis.close();
	    
	    /* set up the authentication parameters for talking to the server */

#ifdef DEMO_USE_SNMP_VERSION_3
	    
	    /* Use SNMPv3 to talk to the experimental server */

	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Using SNMP V3" << std::endl;
	    fpchassis.close();
	    
	    /* set the SNMP version number */
	    session.version=SNMP_VERSION_3;
	    
	    /* set the SNMPv3 user name */
	    session.securityName = strdup("MD5User");
	    session.securityNameLen = strlen(session.securityName);

	    //session.securityLevel = SNMP_SEC_LEVEL_NOAUTHNOPRIV;
	    
	    /* set the security level to authenticated, but not encrypted */
	    session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
	    
	    
	    /* set the authentication method to MD5 */
	    session.securityAuthProto = usmHMACMD5AuthProtocol;
	    session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
	    session.securityAuthKeyLen = USM_AUTH_KU_LEN;
	    
	    /* set the authentication key to a MD5 hashed version of our
	       passphrase "The Net-SNMP Demo Password" (which must be at least 8
	       characters long) */
	    if (generate_Ku(session.securityAuthProto,
			    session.securityAuthProtoLen,
			    (u_char *) our_v3_passphrase, strlen(our_v3_passphrase),
			    session.securityAuthKey,
			    &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
	      snmp_perror(argv[0]);
	      snmp_log(LOG_ERR,
		       "Error generating Ku from authentication pass phrase. \n");
	      exit(1);
	    }

#else /* we'll use the insecure (but simplier) SNMPv1 */


	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Using SNMP V1" << std::endl;
	    fpchassis.close();
	    
	    /* set the SNMP version number */
	    session.version = SNMP_VERSION_1;
	    
	    /* set the SNMPv1 community name used for authentication */
	    session.community = (u_char *)"public";
	    //session.community_len = strlen(session.community);
	    session.community_len = strlen((const char*)session.community);
    
#endif /* SNMPv1 */
    
	    /*
	     * Open the session
		     */
	    SOCK_STARTUP;
	    ss = snmp_open(&session);                     /* establish the session */

	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Establish Session" << std::endl;
	    fpchassis.close();

	    
	    if (!ss)
	      {

		fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
		fpchassis << "snmp demo Session Failed" << std::endl;
		fpchassis.close();
		
		snmp_sess_perror("ack", &session);
		SOCK_CLEANUP;
		exit(1);
	      }

 //struct tree * mib_tree;
 //add_mibdir(".");
  //mib_tree = read_mib("/usr/share/snmp/mibs/");


	    /*
	     * Create the PDU for the data for our request.
	     *   1) We're going to GET the system.sysDescr.0 node.
	     */
	    pdu = snmp_pdu_create(SNMP_MSG_GET);
	    anOID_len = MAX_OID_LEN;
#if 0	    
	    if (!snmp_parse_oid("iso.3.6.1.2.1.1.1.0", anOID, &anOID_len)) {
	      snmp_perror("iso.3.6.1.2.1.1.1.0");
	      SOCK_CLEANUP;
	      exit(1);
	    }
#else
	    /*
	     *  These are alternatives to the 'snmp_parse_oid' call above,
	     *    e.g. specifying the OID by name rather than numerically.
	     */
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Session read object id" << std::endl;
	    fpchassis.close();
	    
	    read_objid("iso.3.6.1.2.1.1.1.0", anOID, &anOID_len);
//	    get_node("sysDescr.0", anOID, &anOID_len);
//	    read_objid("system.sysDescr.0", anOID, &anOID_len);
#endif


	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Session add null variable" << std::endl;
	    fpchassis.close();
	    
	    snmp_add_null_var(pdu, anOID, anOID_len);


	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Session send request out" << std::endl;
	    fpchassis.close();
	    
	    /*
	     * Send the Request out.
	     */
	    status = snmp_synch_response(ss, pdu, &response);

	    
	    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
	    fpchassis << "snmp demo Process the request" << std::endl;
	    fpchassis.close();
	    
	    /*
	     * Process the response.
	     */
	    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
	      {
		fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
		fpchassis << "snmp demo Print the results" << std::endl;
		fpchassis.close();
		
	      /*
	       * SUCCESS: Print the result variables
	       */
	      
	        for(vars = response->variables; vars; vars = vars->next_variable)
		  print_variable(vars->name, vars->name_length, vars);
	      
	      /* manipuate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		  {
		    if (vars->type == ASN_OCTET_STR)
		      {
			char *sp = (char *)malloc(1 + vars->val_len);
			memcpy(sp, vars->val.string, vars->val_len);
			sp[vars->val_len] = '\0';
			printf("value #%d is a string: %s\n", count++, sp);
			free(sp);
		      }
		    else
		      printf("value #%d is NOT a string! Ack!\n", count++);
		  }
	      }
	    else
	      {

		fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
		fpchassis << "snmp demo Print FAILED" << std::endl;
		fpchassis.close();
		/*
		 * FAILURE: print what went wrong!
		 */
	      
		if (status == STAT_SUCCESS)
		  fprintf(stderr, "Error in packet\nReason: %s\n",
			  snmp_errstring(response->errstat));
	      else if (status == STAT_TIMEOUT)
		fprintf(stderr, "Timeout: No response from %s.\n",
			session.peername);
	      else
		snmp_sess_perror("snmpdemoapp", ss);
		
	      }
	    
	    /*
	     * Clean up:
	     *  1) free the response.
	     *  2) close the session.
	     */
	    if (response)
	      snmp_free_pdu(response);
	    snmp_close(ss);
	    
	    SOCK_CLEANUP;
	    return (0);
	}

  int exampleDeamon (void) 
  {
    int agentx_subagent=1; /* change this if you want to be a SNMP master agent */
    int background = 0; /* change this if you want to run in the background */
    int syslog = 0; /* change this if you want to use syslog */

    //long nstAgentSubagentObject = 2;
    //oid nstAgentSubagentObject_oid[] =
    //   { 1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 1, 2, 0 };
    
    /* print log errors to syslog or stderr */
    if (syslog)
      snmp_enable_calllog();
    else
      snmp_enable_stderrlog();
    
    /* we're an agentx subagent? */
    if (agentx_subagent)
      {
	/* make us a agentx client. */
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
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
    //init_netSnmpExampleScalars();
    init_netSnmpHostsTable();
    init_netSnmpControlSmtpScalars();

    
    //init_nstAgentSubagentObject();
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
    //if (!agentx_subagent)
    //init_master_agent();  /* open the port to listen on (defaults to udp:161) */
    
    /* In case we recevie a request to stop (kill -TERM or kill -INT) */
    int keep_running = 1;
    //signal(SIGTERM, stop_server);
    //signal(SIGINT, stop_server);
    
    snmp_log(LOG_INFO,"example-demon is up and running.\n");
    
    /* your main loop here... */
    while(keep_running)
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

  
};

  

int main(int argc, char** argv)
{
    std::ofstream fpchassis;
    fpchassis.open("/tmp/chassis.tmp",std::ios_base::app);
    fpchassis << "SNMP Agent" << std::endl;
    fpchassis.close();

    //lg2::debug("Welcome to SNMP Agent");

    if (!std::filesystem::exists(SnmpTrapStatusFile)) {
        std::ofstream file(SnmpTrapStatusFile, std::ios::out);
        if (file.is_open()) {
          file << std::boolalpha << true << std::endl;
          file.close();
        }
        else{
            std::cerr << "Unable to open file" << SnmpTrapStatusFile << std::endl;
        }
    }

    if (0) {
      argc = argc;
      argv = argv;
    }

    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    // Snmp Object Manager
    sdbusplus::server::manager_t objManager(*conn, "xyz.openbmc_project.Snmp");
    conn->request_name("xyz.openbmc_project.Snmp");

    // Snmp Utils Manager
    auto manager = std::make_unique<SnmpUtilsManager>(*conn, snmpAgentRoot);
    auto manager1 = std::make_unique<SnmpAgentImp>(*conn, snmpAgentRoot);

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

    if (!std::filesystem::exists(snmpdConfExtFileDir)) {
      if (!addCommunityString("rwcommunity", "AMI", "smtp")) {
        std::cerr << " Fail to create AMI extented community string"
                  << std::endl;
      }
    }

    io.run();

    return -1;
}
