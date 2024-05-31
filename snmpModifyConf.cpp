#include "snmpModifyConf.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

const std::string snmpdConfFilepath = "/etc/snmp/snmpd.conf";
const std::string snmpdConfExtFilepath = "/etc/snmp/snmpd.conf.d/snmpd.conf";
const std::string snmpdConfExtFileDir = "/etc/snmp/snmpd.conf.d/";
const std::string snmpConfFilepath = "/etc/snmp/snmp.conf";
const std::string snmpdServiceName = "snmpd.service";

enum class ServiceAction { Start, Stop, Restart };

void controlSystemdService(const std::string &serviceName,
                           ServiceAction action) {

  try {
    auto bus = sdbusplus::bus::new_default();

    std::string methodName;
    if (action == ServiceAction::Start) {
      methodName = "StartUnit";
    } else if (action == ServiceAction::Stop) {
      methodName = "StopUnit";
    } else if (action == ServiceAction::Restart) {
      methodName = "RestartUnit";
    }

    std::string mode = "replace";

    auto msg = bus.new_method_call(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", methodName.c_str());
    msg.append(serviceName, mode);

    bus.call_noreply(msg);

  } catch (const sdbusplus::exception::SdBusError &e) {
    if (action == ServiceAction::Start) {
      std::cerr << "Failed to start service: " << e.what() << std::endl;
    } else if (action == ServiceAction::Stop) {
      std::cerr << "Failed to stop service: " << e.what() << std::endl;
    } else if (action == ServiceAction::Restart) {
      std::cerr << "Failed to Restart service: " << e.what() << std::endl;
    }
  }
}

bool isStringVectorString(const std::vector<std::string> &vectorStr,
                          const std::string &str) {
  for (const auto &String : vectorStr) {
    if (String == str) {
      return true;
    }
  }
  return false;
}

bool isValidAccessType(const std::string &accessType) {
  return accessType == "rocommunity" || accessType == "rwcommunity";
}

std::vector<std::string> listCommunityString() {
  std::vector<std::string> newlyCreatedCommunityString;
  std::string line;
  std::ifstream snmpdConfExtFileStream(snmpdConfExtFilepath);
  if (snmpdConfExtFileStream.is_open()) {
    while (std::getline(snmpdConfExtFileStream, line)) {
      if (line.find("rocommunity ") != std::string::npos ||
          line.find("rwcommunity ") != std::string::npos) {
        size_t pos1 = line.find(" ");
        size_t pos2 = line.find(" default ");
        if (pos1 != std::string::npos && pos2 != std::string::npos) {
          newlyCreatedCommunityString.push_back(
              line.substr(pos1 + 1, pos2 - pos1 - 1));
        }
      }
    }
    snmpdConfExtFileStream.close();
  } else {
    std::cerr << "Unable to open file: " << snmpdConfFilepath << std::endl;
  }
  return newlyCreatedCommunityString;
}

bool removeCommunityString(const std::string &communityString) {
  const std::string tmpConfFilePath = "/etc/snmp/snmpd.conf.d/snmpd_tmp.conf";
  bool communityStringFound = false;
  std::string line;

  std::ifstream snmpdConfExtFileStream(snmpdConfExtFilepath);
  if (!snmpdConfExtFileStream.is_open()) {
    std::cerr << "Unable to open file: " << snmpdConfExtFilepath << "\n";
    return false;
  }

  std::ofstream tmpConfFileStream(tmpConfFilePath);
  if (!tmpConfFileStream.is_open()) {
    std::cerr << "Unable to create temporary file: " << tmpConfFilePath << "\n";
    snmpdConfExtFileStream.close();
    return false;
  }

  while (getline(snmpdConfExtFileStream, line)) {
    std::istringstream lineStream(line);
    std::string firstWord;
    if (!(lineStream >> firstWord)) {
      continue;
    }

    if (firstWord == "rocommunity" || firstWord == "rwcommunity") {
      std::vector<std::string> words;
      std::string word;

      for (char c : line) {
        if (std::isalnum(c) || c == '_') {
          word += c;
        } else {
          if (!word.empty()) {
            words.push_back(word);
            word.clear();
          }
        }
      }
      if (!word.empty()) {
        words.push_back(word);
      }

      auto it =
          std::find_if(words.begin(), words.end(), [&](const std::string &w) {
            return w == communityString;
          });

      if (it != words.end()) {
        communityStringFound = true;
        continue;
      }
    }

    tmpConfFileStream << line << '\n';
  }

  snmpdConfExtFileStream.close();
  tmpConfFileStream.close();

  if (!communityStringFound) {
    std::cerr << "Error: Community string '" << communityString
              << "' not found.\n";
    std::remove(tmpConfFilePath.c_str());
    return false;
  }

  if (std::rename(tmpConfFilePath.c_str(), snmpdConfExtFilepath.c_str()) != 0) {
    std::cerr << "Error renaming temporary config file.\n";
    return false;
  }

  controlSystemdService(snmpdServiceName, ServiceAction::Restart);
  std::cout << "Community string removed successfully.\n";
  return true;
}

std::vector<std::string> listViewAccess() {
  std::vector<std::string> viewAccessParameter;
  std::ifstream snmpdConfFileStream(snmpdConfFilepath);
  std::string line;

  if (!snmpdConfFileStream) {
    std::cerr << "Unable to open file:" << snmpdConfFilepath << std::endl;
    return viewAccessParameter;
  }

  while (std::getline(snmpdConfFileStream, line)) {

    if (line.empty() || line[0] == '#') {
      continue;
    }

    size_t pos1 = line.find("view ");
    size_t pos2 = line.find(" included");

    if (pos1 != std::string::npos && pos2 != std::string::npos) {
      std::string viewName = line.substr(pos1 + 5, pos2 - (pos1 + 5));

      viewName.erase(
          std::remove_if(viewName.begin(), viewName.end(), ::isspace),
          viewName.end());

      if (!viewName.empty()) {
        viewAccessParameter.push_back(viewName);
      }
    }
  }

  snmpdConfFileStream.close();
  return viewAccessParameter;
}

bool addCommunityString(const std::string &accessType,
                        const std::string &communityString,
                        const std::string &viewAccess) {

  if (!isValidAccessType(accessType)) {
    std::cerr << "Invalid access type. It must be either rocommunity or "
                 "rwcommunity.\n";
    return false;
  }

  std::vector<std::string> ViewAccess = listViewAccess();

  std::vector<std::string> CommunityString = listCommunityString();

  if (!isStringVectorString(ViewAccess, viewAccess) ||
      (isStringVectorString(CommunityString, communityString)) ||
      (communityString == "public")) {
    std::cerr << "Invalid parameter.\n";
    return false;
  }

  std::ofstream extSnmpdConfFile(snmpdConfExtFilepath, std::ios::app);

  if (!std::filesystem::exists(snmpdConfExtFileDir)) {
    std::filesystem::create_directory(snmpdConfExtFileDir);
  }

  if (!extSnmpdConfFile.is_open()) {
    std::ofstream createFile(snmpdConfExtFilepath);
    if (!createFile.is_open()) {
      std::cerr << "Unable to create file: " << strerror(errno) << std::endl;
      return false;
    }
    createFile.close();
    extSnmpdConfFile.open(snmpdConfExtFilepath, std::ios::app);
    extSnmpdConfFile << "\n # AMI Extended snmpd.conf file" << std::endl;
  }

  extSnmpdConfFile << accessType << " " << communityString << " default -V "
                   << viewAccess << std::endl;
  extSnmpdConfFile.close();
  controlSystemdService(snmpdServiceName, ServiceAction::Restart);

  std::cout << "Community string added successfully.\n";

  return true;
}

void registerSnmpdDbus(
    std::shared_ptr<sdbusplus::asio::dbus_interface> ifaceSnmpdConf) {

  ifaceSnmpdConf->register_method("AddCommunityString", addCommunityString);
  ifaceSnmpdConf->register_method("RemoveCommunityString",
                                  removeCommunityString);
  ifaceSnmpdConf->register_method("ListNewlyCreatedCommunityString",
                                  listCommunityString);
  ifaceSnmpdConf->register_method("ListViewAccess", listViewAccess);

  ifaceSnmpdConf->initialize();
}

void SetSnmpVersionStatus(const std::string &version, bool setStatus) {

  std::string line;
  std::string updatedContent;
  bool found = false;

  std::ifstream snmpConfFileStream(snmpConfFilepath);
  if (!snmpConfFileStream) {
    std::ofstream createFile(snmpConfFilepath);
    if (!createFile) {
      std::cerr << "Error: Failed to create file:" << snmpConfFilepath
                << std::endl;
      return;
    }
    createFile.close();
    std::cout << "Created snmp.conf file." << std::endl;
  }
  snmpConfFileStream.close();

  std::ifstream configFileRead(snmpConfFilepath);
  if (!configFileRead) {
    std::cerr << "Error: Unable to open snmp.conf file." << std::endl;
    return;
  }

  while (std::getline(configFileRead, line)) {
    if (line.find(version) != std::string::npos) {
      updatedContent += version + " " + (setStatus ? "1" : "0") + "\n";
      found = true;
    } else {
      updatedContent += line + "\n";
    }
  }
  configFileRead.close();

  if (!found) {
    updatedContent += version + " " + (setStatus ? "1" : "0") + "\n";
  }

  std::ofstream configFileWrite(snmpConfFilepath);
  if (!configFileWrite) {
    std::cerr << "Error: Unable to write in file:" << snmpConfFilepath
              << std::endl;
    return;
  }
  configFileWrite << updatedContent;
  configFileWrite.close();

  std::cout << "SNMP configuration for " << version << " updated successfully."
            << std::endl;
  controlSystemdService(snmpdServiceName, ServiceAction::Restart);
}

bool getSnmpVersionStatus(const std::string &version) {

  std::string line, status;
  std::ifstream configFile(snmpConfFilepath);
  if (!configFile) {
    return false;
  }

  while (std::getline(configFile, line)) {
    if (line.find(version) != std::string::npos) {
      std::istringstream lineStream(line);
      while (lineStream >> status) {
      }
      return (status == "1" || status == "true" || status == "yes");
    }
  }

  return false;
}

void registerSnmpDbus(
    std::shared_ptr<sdbusplus::asio::dbus_interface> ifaceSnmpConf) {

  bool disableSNMPv1Status = false;
  bool disableSNMPv2cstatus = false;
  bool disableSNMPv3Status = false;

  ifaceSnmpConf->register_property(
      "disableSNMPv1", disableSNMPv1Status,
      [&](const bool &req, bool &res) {
        if (req == res) {
          return 1;
        }
        SetSnmpVersionStatus("disableSNMPv1", req);
        res = req;
        return 1;
      },
      [&](bool &res) {
        res = getSnmpVersionStatus("disableSNMPv1");
        return res;
      });

  ifaceSnmpConf->register_property(
      "disableSNMPv2c", disableSNMPv2cstatus,
      [&](const bool &req, bool &res) {
        if (req == res) {
          return 1;
        }
        SetSnmpVersionStatus("disableSNMPv2c", req);
        res = req;
        return 1;
      },
      [&](bool res) {
        res = getSnmpVersionStatus("disableSNMPv2c");
        return res;
      });

  ifaceSnmpConf->register_property(
      "disableSNMPv3", disableSNMPv3Status,
      [&](const bool &req, bool &res) {
        if (req == res) {
          return 1;
        }
        SetSnmpVersionStatus("disableSNMPv3", req);
        res = req;
        return 1;
      },
      [&](bool &res) {
        res = getSnmpVersionStatus("disableSNMPv3");
        return res;
      });
  ifaceSnmpConf->initialize();
}
