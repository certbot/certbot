"""A class that performs server.xml parsing for Tomcat"""

import logging
from lxml import etree

from certbot import errors
from certbot.compat import os


logger = logging.getLogger(__name__)


class TomcatParser(object):
    """File parser for Tomcat"""

    def __init__(self, root):
        self.tree = None
        self.root = os.path.abspath(root)
        self.config_root = self._find_config_root()
        self.load()

    def load(self):
        self._open_and_parse_file()

    def _find_config_root(self):
        """Return the tomcat server.xml Root file."""
        location = ['server.xml']

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.NoInstallationError(
            "Could not find tomcat root configuration file (server.xml)")

    def _open_and_parse_file(self):
        self.tree = etree.parse(self.config_root)

    def _process_cert_change(self, domain, certpath, keypath):
        attr_cert = {"certificateKeyFile": keypath, "certificateFile": certpath,
                     "type": "RSA"}        
        hostNameFound = False
        print("CN: ",domain)
        root = self.tree.getroot()
        if domain.startswith("*."):
            print("installing wildcard cert..")
            for child in root.iter("Connector"):
                print("looping connector with port: ",child.attrib["port"])
                domainPattern = domain[2:]
                print("cn pattern ends with: ",domainPattern)
                if not len(child) == 0:
                    for ele in child:
                        if ele.tag.__eq__("SSLHostConfig"):
                            if "hostName" in ele.attrib:
                                print("configured hostName: ", ele.attrib["hostName"])                            
                                if (ele.attrib["hostName"].lower().endswith(domainPattern.lower())):
                                    is_certificate = False
                                    hostNameFound=True
                                    print("matched")
                                    for childEle in ele:
                                        if childEle.tag.__eq__("Certificate"):
                                            childEle.attrib["certificateFile"] = certpath
                                            childEle.attrib["certificateKeyFile"] = keypath
                                            childEle.attrib["type"] = "RSA"
                                            childEle.attrib.pop("certificateChainFile", None)
                                            childEle.attrib.pop("certificateKeystoreFile", None)
                                            is_certificate = True
                                    if not is_certificate:
                                        ele.append(etree.Element("Certificate", attrib=attr_cert))
                                    if child.attrib['port'].__eq__('80'):
                                        child.attrib['port'] = "443" #Support 80->443 redirect
                                    child.attrib['SSLEnabled'] = "true"
                                    is_certificate = False
        else:        
            for child in root.iter("Connector"):
                print("looping connector with port: ",child.attrib["port"])
                if not len(child) == 0:
                    for ele in child:
                        if ele.tag.__eq__("SSLHostConfig"):
                            if "hostName" in ele.attrib:
                                print("configured hostName: ", ele.attrib["hostName"])                            
                                if domain.lower().__eq__(ele.attrib["hostName"].lower()):
                                    is_certificate = False
                                    hostNameFound=True
                                    print("matched")
                                    for childEle in ele:
                                        if childEle.tag.__eq__("Certificate"):
                                            childEle.attrib["certificateFile"] = certpath
                                            childEle.attrib["certificateKeyFile"] = keypath
                                            childEle.attrib["type"] = "RSA"
                                            childEle.attrib.pop("certificateChainFile", None)
                                            childEle.attrib.pop("certificateKeystoreFile", None)
                                            is_certificate = True
                                    if not is_certificate:
                                        ele.append(etree.Element("Certificate", attrib=attr_cert))
                                    if child.attrib['port'].__eq__('80'):
                                        child.attrib['port'] = "443" #Support 80->443 redirect
                                    child.attrib['SSLEnabled'] = "true"
                                    is_certificate = False
        if not hostNameFound:
            raise errors.NoInstallationError("could not find provided domain name as server name in server.xml")

    def _save_modified(self):
        self.tree.write(self.config_root,encoding="UTF-8",xml_declaration=True)