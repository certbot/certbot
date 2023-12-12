"""Tomcat Configuration"""
import zope.interface
import logging
import platform
import subprocess
import time
import glob

from acme import challenges
from certbot import interfaces
from certbot import errors
from certbot import util
from certbot.compat import os
from certbot.compat import filesystem
from certbot.plugins import common
from certbot_tomcat._internal import constants
from certbot_tomcat._internal import tomcat_http_01
from certbot_tomcat._internal import tomcat_parser

logger = logging.getLogger(__name__)
@zope.interface.implementer(interfaces.IAuthenticator, interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class TomcatConfigurator(common.Installer):
    description = "Tomcat Web Server plugin"

    @classmethod
    def add_parser_arguments(cls, add):
        logger.debug("********* Inside add_parser_arguments *********")
        default_server_root = _determine_default_server_root()
        add("server-root", default=constants.CLI_DEFAULTS["server_root"],
            help="Tomcat server root directory. (default: %s)" % default_server_root)
        add("ctl", default=constants.CLI_DEFAULTS["ctl"], help="Path to the "
                                                               "'tomcat' binary, used for 'configtest' and retrieving tomcat "
                                                               "version number.")
        add("service-name", default=constants.CLI_DEFAULTS["service_name"], help="service name if running as a service")

    def prepare(self):
        logger.debug("******* Inside prepare*************")
        logger.debug("value for self" + self.conf('ctl'))
        if not util.exe_exists(self.conf('ctl')):
            raise errors.NoInstallationError(
                "Could not find a usable 'tomcat' binary. Ensure tomcat exists, "
                "the binary is executable, and your PATH is set correctly.")
        self.parser = tomcat_parser.TomcatParser(self.conf("server-root"))



    def __init__(self, *args, **kwargs):
        """Initialize an Tomcat Configurator.

        :param tup version: version of Tomcat as a tuple (1, 4, 7)
            (used mostly for unittesting)

        :param tup openssl_version: version of OpenSSL linked to Tomcat as a tuple (1, 4, 7)
            (used mostly for unittesting)

        """
        version = kwargs.pop("version", None)
        openssl_version = kwargs.pop("openssl_version", None)
        super(TomcatConfigurator, self).__init__(*args, **kwargs)

        # Add number of outstanding challenges
        self._chall_out = 0
        self.parser = None
        self.server_restart = args[0].restart
        logger.info("Server restart:%s", self.server_restart)

    def get_chall_pref(self, unused_domain):
        """Return list of challenge preferences."""
        return [challenges.HTTP01]

    # Entry point in main.py for performing challenges
    def perform(self, achalls):
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out += len(achalls)
        responses = [None] * len(achalls)
        http_doer = tomcat_http_01.TomcatHttp01(self)

        for i, achall in enumerate(achalls):
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            http_doer.add_chall(achall, i)

        http_response = http_doer.perform()
        # Must restart in order to activate the challenges.
        # Handled here because we may be able to load up other challenge types
        #self.restart()

        # Go through all of the challenges and assign them to the proper place
        # in the responses return value. All responses must be in the same order
        # as the original challenges.
        for i, resp in enumerate(http_response):
            responses[http_doer.indices[i]] = resp

        return responses

    # called after challenges are performed
    def cleanup(self, achalls):
        """Revert all challenges."""
        self._chall_out -= len(achalls)

        # If all of the challenges have been finished, clean up everything
        if self._chall_out <= 0:
            print()
            #self.revert_challenge_config()
            #self.restart()

    def get_all_names(self):  # type: ignore
        """Returns all names that may be authenticated.

        :rtype: `collections.Iterable` of `str`

        """
        logger.debug("********inside get all names************")

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        """Deploy certificate.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)

        :raises .PluginError: when cert cannot be deployed

        """
        if not fullchain_path:
            raise errors.PluginError(
                "The tomcat plugin currently requires --fullchain-path to "
                "install a cert.")
        logger.debug("domain name "+domain)
        logger.debug("cert path "+cert_path)
        logger.debug("chain_path path "+chain_path)
        logger.debug("fullchain_path path "+fullchain_path)
        self.parser._process_cert_change(domain,cert_path,key_path)


    def enhance(self, domain, enhancement, options=None):
        """Perform a configuration enhancement.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
            for expected options for each enhancement.

        :raises .PluginError: If Enhancement is not supported, or if
            an error occurs during the enhancement.

        """

    def supported_enhancements(self):  # type: ignore
        """Returns a `collections.Iterable` of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :rtype: :class:`collections.Iterable` of :class:`str`

        """
        return []

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint.

        It is assumed that at most one checkpoint is finalized by this
        method. Additionally, if an exception is raised, it is assumed a
        new checkpoint was not finalized.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)

        :raises .PluginError: when save is unsuccessful

        """
        self.parser._save_modified()

    def rollback_checkpoints(self, rollback=1):
        """Revert `rollback` number of configuration checkpoints.

        :raises .PluginError: when configuration cannot be fully reverted

        """

    def recovery_routine(self):  # type: ignore
        """Revert configuration to most recent finalized checkpoint.

        Remove all changes (temporary and permanent) that have not been
        finalized. This is useful to protect against crashes and other
        execution interruptions.

        :raises .errors.PluginError: If unable to recover the configuration

        """
        print("No recovery routine")


    def config_test(self):  # type: ignore
        """Make sure the configuration is valid.

        :raises .MisconfigurationError: when the config is not in a usable state

        """
    def _get_service_status(self,serviceName) :
        """check service status
        Currently accomodated for windows based service
        Returns Status for service
        """
        status = ""
        line = ["sc",'query', serviceName]
        p = subprocess.Popen(line, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True, env=None,shell = True)
        out, err = p.communicate()      
        if p.returncode == 0: 
            status_line_data=out.split("\n")
            for i in status_line_data:
                if 'STATE' in i: 
                    logger.debug(i) 
                    status = i
        else :
            logger.debug("command returncode:"+str(p.returncode))
        return status

    def _check_and_wait_service(self,serviceName, expectedstatus) :
        """check and wait service status until it gets expectedstatus
        or timeout with 2 minues seconds, whichever occurs first

        Currently accomodated for windows based service
        Returns Ststus for success scenario, else empty on timeout
        """
        validstatus = 0
        status = ""
        count = 60
        while validstatus == 0 and count != 0:     
            logger.debug("Checking tomcat service status..")  
            time.sleep(2) 
            count = count - 1                   
            line = ["sc",'query', serviceName]
            p = subprocess.Popen(line, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True, env=None,shell = True)
            out, err = p.communicate()      
            if p.returncode == 0: 
                status_line_data=out.split("\n")
                for i in status_line_data:
                    if 'STATE' in i: 
                        logger.debug(i)          
                    if expectedstatus in str(i):
                            validstatus = 1
                            status = expectedstatus
            else :
                logger.debug("command returncode:"+str(p.returncode))
                break
        return status

    
    def restart(self):  # type: ignore
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted

        """
        if self.server_restart == "true":
            print("*********** ReStart Initiated ********* ")
            try:
                if self.conf("service-name"):
                    logger.debug("Restarting tomcat as a service..")
                    if platform.system() in ('Windows'):
                        service_name = self.conf("service-name")
                        logger.debug("Service Name: "+service_name)
                        logger.debug("Checking initial Service status ")
                        status = self._get_service_status(service_name)
                        if "RUNNING" in status:
                            logger.debug("Stopping tomcat service ")
                            value = subprocess.call('''sc stop ''' + service_name, shell=True)
                        service_status=self._check_and_wait_service(service_name, "STOPPED")
                        logger.debug("Service Stop completes with status:- "+service_status)
                        status = self._get_service_status(service_name)
                        if "STOPPED" in status:
                            logger.debug("Starting tomcat service ")
                            value = subprocess.call('''sc start ''' + service_name, shell=True)
                        service_status=self._check_and_wait_service(service_name, "RUNNING")
                        logger.debug("Service Start completes with status:- "+service_status)
                    else:
                        value = subprocess.call('''service ''' + self.conf("service-name")+''' stop ''', shell=True)
                        time.sleep(20)
                        value = subprocess.call('''service ''' + self.conf("service-name")+''' start ''', shell=True)

                else:
                    os.environ["CATALINA_HOME"] = (os.path.dirname(os.path.dirname(filesystem.realpath(self.conf("ctl")))))
                    os.environ["CATALINA_BASE"] = (os.path.dirname(filesystem.realpath(self.conf("server-root"))))
                    logger.debug("Restarting tomcat as a process")
                    if platform.system() in ('Windows'):
                        command = self.conf("ctl")
                        logger.debug("tomcat process shutdown command: "+command)
                        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True, env=None,shell = True)
                        out, err = p.communicate() 
                        logger.debug("tomcat process shutdown returncode:"+str(p.returncode))     
                        if p.returncode != 0:
                            logger.debug("command returncode:"+str(p.returncode))
                            logger.debug(err)
                            logger.debug(out)
                            raise Exception("Fail to stop tomcat")                    
                        time.sleep(20)
                        command = command.replace("shutdown.bat", "startup.bat")
                        logger.debug("tomcat process startup command: "+command)
                        with open(os.devnull, 'w')  as FNULL:
                            value = subprocess.call(command,stdout=FNULL, stderr=FNULL, shell=True)
                            logger.debug("tomcat process startup returncode:"+str(value))     
                    else:
                        value = subprocess.call(self.conf("ctl"), shell=True)
                        time.sleep(20)
                        value = subprocess.call(self.conf("ctl").replace("shutdown.sh", "startup.sh"), shell=True)
            except (OSError, ValueError):
                raise errors.MisconfigurationError("Tomcat restart failed")
        else:
            logger.info("Not restarting server")

    def more_info(self):
        """Human-readable string to help understand the module"""
        return (
            "Configures tomcat to authenticate and install HTTPS.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep, root=self.parser.config_root,
                version=".".join(str(i) for i in self.version))
        )

def _determine_default_server_root():
    if os.environ.get("CERTBOT_DOCS") == "1":
        default_server_root = "%s or %s" % (constants.LINUX_SERVER_ROOT,
            constants.FREEBSD_DARWIN_SERVER_ROOT)
    else:
        default_server_root = constants.CLI_DEFAULTS["server_root"]
    return default_server_root

