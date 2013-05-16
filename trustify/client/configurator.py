import augeas
import subprocess
import re
import os
import sys
import stat
import socket
import time
import shutil

from trustify.client.CONFIG import SERVER_ROOT, BACKUP_DIR, MODIFIED_FILES
#from CONFIG import SERVER_ROOT, BACKUP_DIR, MODIFIED_FILES, REWRITE_HTTPS_ARGS, CONFIG_DIR, WORK_DIR
from trustify.client.CONFIG import REWRITE_HTTPS_ARGS, CONFIG_DIR, WORK_DIR
from trustify.client import logger
#import logger

# Question: Am I missing any attacks that can result from modifying CONFIG file?
# Configurator should be turned into a Singleton

class VH(object):
    def __init__(self, filename_path, vh_path, vh_addrs, is_ssl, is_enabled):
        self.file = filename_path
        self.path = vh_path
        self.addrs = vh_addrs
        self.names = []
        self.ssl = is_ssl
        self.enabled = is_enabled

    def set_names(self, listOfNames):
        self.names = listOfNames

    def add_name(self, name):
        self.names.append(name)

class Configurator(object):
    
    def __init__(self, server_root=SERVER_ROOT):
        # TODO: this instantiation can be optimized to only load Httd 
        #       relevant files
        # Set Augeas flags to save backup
        self.aug = augeas.Augeas(None, None, 1 << 0)
        self.standardize_excl()

        self.save_notes = ""
        # new_files is for save checkpoints and to allow reverts
        self.new_files = []
        self.vhosts = self.get_virtual_hosts()
        # Add name_server association dict
        self.assoc = dict()
        # Verify that all directories exist with proper permissions
        self.verify_dir_setup()
        # See if any temporary changes need to be recovered
        self.recovery_routine()

    # TODO: This function can be improved to ensure that the final directives 
    # are being modified whether that be in the include files or in the 
    # virtualhost declaration - these directives can be overwritten
    def deploy_cert(self, vhost, cert, key, cert_chain=None):
        """
        Currently tries to find the last directives to deploy the cert in
        the given virtualhost.  If it can't find the directives, it searches
        the "included" confs.  The function verifies that it has located 
        the three directives and finally modifies them to point to the correct
        destination
        TODO: Make sure last directive is changed
        TODO: Might be nice to remove chain directive if none exists
              * This shouldn't happen within trustify though
        """
        search = {}
        path = {}
        
        path["cert_file"] = self.find_directive("SSLCertificateFile", None, vhost.path)
        path["cert_key"] = self.find_directive("SSLCertificateKeyFile", None, vhost.path)

        # Only include if a certificate chain is specified
        if cert_chain is not None:
            path["cert_chain"] = self.find_directive("SSLCertificateChainFile", None, vhost.path)
        
        if len(path["cert_file"]) == 0 or len(path["cert_key"]) == 0:
            # Throw some "can't find all of the directives error"
            logger.warn("Warn: cannot find a cert or key directive in " + vhost.path)
            logger.warn("VirtualHost was not modified")
            # Presumably break here so that the virtualhost is not modified
            return False
        
        logger.info("Deploying Certificate to VirtualHost %s" % vhost.file)
            
        self.aug.set(path["cert_file"][0], cert)
        self.aug.set(path["cert_key"][0], key)
        if cert_chain is not None:
            if len(path["cert_chain"]) == 0:
                self.add_dir(vhost.path, "SSLCertificateChainFile", cert_chain)
            else:
                self.aug.set(path["cert_chain"][0], cert_chain)
        
        self.save_notes += "Changed vhost at %s with addresses of %s\n" % (vhost.file, vhost.addrs)
        self.save_notes += "\tSSLCertificateFile %s\n" % cert
        self.save_notes += "\tSSLCertificateKeyFile %s\n" % key
        if cert_chain:
            self.save_notes += "\tSSLCertificateChainFile %s\n" % cert_chain
        # This is a significant operation, make a checkpoint
        return self.save("Virtual Server - deploying certificate", False)

    def choose_virtual_host(self, name, ssl=True):
        """
        Chooses a virtual host based on the given domain name

        returns: VH object
        TODO: This should return list if no obvious answer is presented
        """
        # Allows for domain names to be associated with a virtual host
        # Client isn't using create_dn_server_assoc(self, dn, vh) yet
        for dn, vh in self.assoc:
            if dn == name:
                return vh
        # Check for servernames/aliases for ssl hosts
        for v in self.vhosts:
            if v.ssl == True:
                for n in v.names:
                    if n == name:
                        return v
        # Checking for domain name in vhost address
        # This technique is not recommended by Apache but is valid
        for v in self.vhosts:
            for a in v.addrs:
                tup = a.partition(":")
                if tup[0] == name and tup[2] == "443":
                    return v

        # Check for non ssl vhosts with servernames/aliases == 'name'
        for v in self.vhosts:
            if v.ssl == False:
                for n in v.names:
                    if n == name:
                        # Must create ssl equivalent vhost
                        return self.make_vhost_ssl(v)

        # No matches, search for the default
        for v in self.vhosts:
            for a in v.addrs:
                if a == "_default_:443":
                    return v
        return None

    def create_dn_server_assoc(self, dn, vh):
        """
        Create an association for domain name with a server
        Helps to choose an appropriate vhost
        """
        self.assoc[dn] = vh
        return
                    
    def get_all_names(self):
        """
        Returns all names found in the Apache Configuration
        Returns all ServerNames, ServerAliases, and reverse DNS entries for
        virtual host addresses
        """
        all_names = set()

        # Kept in same function to avoid multiple compilations of the regex
        priv_ip_regex = "(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
        privateIPs = re.compile(priv_ip_regex)

        for v in self.vhosts:
            all_names.update(v.names)
            for a in v.addrs:
                a_tup = a.partition(":")

                # If it isn't a private IP, do a reverse DNS lookup
                if not privateIPs.match(a_tup[0]):
                    try:
                        socket.inet_aton(a_tup[0])
                        all_names.add(socket.gethostbyaddr(a_tup[0])[0])
                    except (socket.error, socket.herror, socket.timeout):
                        continue

        return all_names

    def __is_private_ip(ipaddr):
        re.compile()
        

    def __add_servernames(self, host):
        """
        Helper function for get_virtual_hosts()
        """
        # This is case sensitive, but Apache is case insensitve
        # Spent 2 days trying to get case insensitive search to work
        # it should be possible as of .7 with /i or 'append i' but I have been
        # unsuccessful thus far
        nameMatch = self.aug.match(host.path + "//*[self::directive=~regexp('[sS]erver[nN]ame')] | " + host.path + "//*[self::directive=~regexp('[sS]erver[aA]lias')]")
        for name in nameMatch:
            args = self.aug.match(name + "/*")
            for arg in args:
                host.add_name(self.aug.get(arg))
    

    def __create_vhost(self, path):
        """
        Private function used by get_virtual_hosts to create vhost objects
        """
        addrs = []
        args = self.aug.match(path + "/arg")
        for arg in args:
            addrs.append(self.aug.get(arg))
        is_ssl = False
        if len(self.find_directive("SSLEngine", "on", path)) > 0:
            is_ssl = True
        filename = self.get_file_path(path)
        is_enabled = self.is_site_enabled(filename)
        vhost = VH(filename, path, addrs, is_ssl, is_enabled)
        self.__add_servernames(vhost)
        return vhost

    def get_virtual_hosts(self):
        """
        Returns list of virtual hosts found in the Apache configuration
        """
        #Search sites-available, httpd.conf for possible virtual hosts
        paths = self.aug.match("/files" + SERVER_ROOT + "sites-available//VirtualHost")
        vhs = []
        for p in paths:
            vhs.append(self.__create_vhost(p))

        return vhs

    def is_name_vhost(self, addr):
        """
        Checks if addr has a NameVirtualHost directive in the Apache config
        addr:    string
        """
        # search for NameVirtualHost directive for ip_addr
        # check httpd.conf, ports.conf, 
        # note ip_addr can be FQDN although Apache does not recommend it
        paths = self.find_directive("NameVirtualHost", None)
        name_vh = []
        for p in paths:
            name_vh.append(self.aug.get(p))
        
        # TODO: Reread NameBasedVirtual host matching... I think it must be an
        #       exact match
        # Check for exact match
        for vh in name_vh:
            if vh == addr:
                return True
        # Check for general IP_ADDR name_vh
        tup = addr.partition(":")
        for vh in name_vh:
            if vh == tup[0]:
                return True
        # Check for straight wildcard name_vh
        for vh in name_vh:
            if vh == "*":
                return True
        # NameVirtualHost directive should be added for this address
        return False

    def add_name_vhost(self, addr):
        """
        Adds NameVirtualHost directive for given address
        Directive is added to ports.conf unless the file doesn't exist
        It is added to httpd.conf as a backup
        """
        aug_file_path = "/files" + SERVER_ROOT + "ports.conf"
        self.add_dir_to_ifmodssl(aug_file_path, "NameVirtualHost", addr)
        
        if len(self.find_directive("NameVirtualHost", addr)) == 0:
            logger.warn("ports.conf is not included in your Apache config...")
            logger.warn("Adding NameVirtualHost directive to httpd.conf")
            self.add_dir_to_ifmodssl("/files" + SERVER_ROOT + "httpd.conf", "NameVirtualHost", addr)
        
        self.save_notes += 'Setting %s to be NameBasedVirtualHost\n' % addr

    def add_dir_to_ifmodssl(self, aug_conf_path, directive, val):
        """
        Adds given directived and value along configuration path within 
        an IfMod mod_ssl.c block.  If the IfMod block does not exist in
        the file, it is created.
        """

        # TODO: Add error checking code... does the path given even exist?
        #       Does it throw exceptions?
        ifModPath = self.get_ifmod(aug_conf_path, "mod_ssl.c")
        # IfModule can have only one valid argument, so append after
        self.aug.insert(ifModPath + "arg", "directive", False)
        nvhPath = ifModPath + "directive[1]"
        self.aug.set(nvhPath, directive)
        self.aug.set(nvhPath + "/arg", val)

    def make_server_sni_ready(self, vhost, default_addr="*:443"):
        """
        Checks to see if the server is ready for SNI challenges
        """
        # Check if mod_ssl is loaded
        if not self.check_ssl_loaded():
            logger.error("Please load the SSL module with Apache")
            return False

        # Check for Listen 443
        # TODO: This could be made to also look for ip:443 combo
        # TODO: Need to search only open directives and IfMod mod_ssl.c
        if len(self.find_directive("Listen", "443")) == 0:
            logger.debug("No Listen 443 directive found")
            logger.debug("Setting the Apache Server to Listen on port 443")
            self.add_dir_to_ifmodssl("/files" + SERVER_ROOT + "ports.conf", "Listen", "443")
            self.save_notes += "Added Listen 443 directive to ports.conf\n"

        # Check for NameVirtualHost
        # First see if any of the vhost addresses is a _default_ addr
        for addr in vhost.addrs:
            tup = addr.partition(":") 
            if tup[0] == "_default_":
                if not self.is_name_vhost(default_addr):
                    logger.debug("Setting all VirtualHosts on " + default_addr + " to be name based virtual hosts")
                    self.add_name_vhost(default_addr)

                return True
        # No default addresses... so set each one individually
        for addr in vhost.addrs:
            if not self.is_name_vhost(addr):
                logger.debug("Setting VirtualHost at" + addr + "to be a name based virtual host")
                self.add_name_vhost(addr)
        
        return True

    def get_ifmod(self, aug_conf_path, mod):
        """
        Returns the path to <IfMod mod>.  Creates the block if it does
        not exist
        """
        ifMods = self.aug.match(aug_conf_path + "/IfModule/*[self::arg='" + mod + "']")
        if len(ifMods) == 0:
            self.aug.set(aug_conf_path + "/IfModule[last() + 1]", "")
            self.aug.set(aug_conf_path + "/IfModule[last()]/arg", mod)
            ifMods = self.aug.match(aug_conf_path + "/IfModule/*[self::arg='" + mod + "']")
        # Strip off "arg" at end of first ifmod path
        return ifMods[0][:len(ifMods[0]) - 3]
    
    def add_dir(self, aug_conf_path, directive, arg):
        """
        Appends directive to end of file given by aug_conf_path
        """
        self.aug.set(aug_conf_path + "/directive[last() + 1]", directive)
        if type(arg) is not list:
            self.aug.set(aug_conf_path + "/directive[last()]/arg", arg)
        else:
            for i in range(len(arg)):
                self.aug.set(aug_conf_path + "/directive[last()]/arg["+str(i+1)+"]", arg[i]) 
            
        
    def find_directive(self, directive, arg=None, start="/files"+SERVER_ROOT+"apache2.conf"):
        """
        Recursively searches through config files to find directives
        TODO: arg should probably be a list
        """
        if arg is None:
            matches = self.aug.match(start + "//* [self::directive='"+directive+"']/arg")
        else:
            matches = self.aug.match(start + "//* [self::directive='" + directive+"']/* [self::arg='" + arg + "']")
            
        includes = self.aug.match(start + "//* [self::directive='Include']/* [label()='arg']")

        for include in includes:
            matches.extend(self.find_directive(directive, arg, self.get_include_path(self.strip_dir(start[6:]), self.aug.get(include))))
        
        return matches

    def strip_dir(self, path):
        """
        Precondition: file_path is a file path, ie. not an augeas section 
                      or directive path
        Returns the current directory from a file_path along with the file
        """
        index = path.rfind("/")
        if index > 0:
            return path[:index+1]
        # No directory
        return ""

    def get_include_path(self, cur_dir, arg):
        """
        Converts an Apache Include directive argument into an Augeas 
        searchable path
        Returns path string
        """
        # Standardize the include argument based on server root
        if not arg.startswith("/"):
            arg = cur_dir + arg
        # conf/ is a special variable for ServerRoot in Apache
        elif arg.startswith("conf/"):
            arg = SERVER_ROOT + arg[5:]
        # TODO: Test if Apache allows ../ or ~/ for Includes
 
        # Attempts to add a transform to the file if one does not already exist
        self.parse_file(arg)
        
        # Argument represents an fnmatch regular expression, convert it
        # Split up the path and convert each into an Augeas accepted regex
        # then reassemble
        if "*" in arg or "?" in arg:
            postfix = ""
            splitArg = arg.split("/")
            for idx, split in enumerate(splitArg):
                # * and ? are the two special fnmatch characters 
                if "*" in split or "?" in split:
                    # Check to make sure only expected characters are used
                    validChars = re.compile("[a-zA-Z0-9.*?]*")
                    matchObj = validChars.match(split)
                    if matchObj.group() != split:
                        logger.error("Error: Invalid regexp characters in "+arg)
                        return []
                    # Turn it into a augeas regex
                    # TODO: Can this instead be an augeas glob instead of regex
                    splitArg[idx] = "* [label() =~ regexp('" + self.fnmatch_to_re(split) + "')]"
            # Reassemble the argument
            arg = "/".join(splitArg)
                    
        # If the include is a directory, just return the directory as a file
        if arg.endswith("/"):
            return "/files" + arg[:len(arg)-1]
        return "/files"+arg

    def check_ssl_loaded(self):
        """
        Checks apache2ctl to get loaded module list
        """
        try:
            #p = subprocess.check_output(['sudo', '/usr/sbin/apache2ctl', '-M'], stderr=open("/dev/null", 'w'))
            p = subprocess.Popen(['sudo', '/usr/sbin/apache2ctl', '-M'], stdout=subprocess.PIPE, stderr=open("/dev/null", 'w')).communicate()[0]
        except:
            logger.error("Error accessing apache2ctl for loaded modules!")
            logger.error("This may be caused by an Apache Configuration Error")
            return False
        if "ssl_module" in p:
            return True
        return False

    def make_vhost_ssl(self, nonssl_vhost):
        """
        Duplicates vhost and adds default ssl options
        New vhost will reside as (nonssl_vhost.path)-trustify-ssl
        """
        avail_fp = nonssl_vhost.file
        # Copy file
        ssl_fp = avail_fp + "-trustify-ssl"
        orig_file = open(avail_fp, 'r')
        new_file = open(ssl_fp, 'w')
        new_file.write("<IfModule mod_ssl.c>\n")
        for line in orig_file:
            new_file.write(line)
        new_file.write("</IfModule>\n")
        orig_file.close()
        new_file.close()
        # This is used for checkpoints
        self.new_files.append(ssl_fp)
        self.aug.load()
        # Delete the VH addresses because they may change here
        del nonssl_vhost.addrs[:]
        ssl_addrs = []

        # change address to address:443, address:80
        ssl_addr_p = self.aug.match("/files"+ssl_fp+"//VirtualHost/arg")
        avail_addr_p = self.aug.match("/files"+avail_fp+"//VirtualHost/arg")
        for i in range(len(avail_addr_p)):
            avail_old_arg = self.aug.get(avail_addr_p[i])
            ssl_old_arg = self.aug.get(ssl_addr_p[i])
            avail_tup = avail_old_arg.partition(":")
            ssl_tup = ssl_old_arg.partition(":")
            avail_new_addr = avail_tup[0] + ":80"
            ssl_new_addr = ssl_tup[0] + ":443"
            self.aug.set(avail_addr_p[i], avail_new_addr)
            self.aug.set(ssl_addr_p[i], ssl_new_addr)
            nonssl_vhost.addrs.append(avail_new_addr)
            ssl_addrs.append(ssl_new_addr)

        # Add directives
        vh_p = self.aug.match("/files"+ssl_fp+"//VirtualHost")
        if len(vh_p) != 1:
            logger.error("Error: should only be one vhost in %s" % avail_fp)
            sys.exit(1)

        self.add_dir(vh_p[0], "SSLCertificateFile", "/etc/ssl/certs/ssl-cert-snakeoil.pem")
        self.add_dir(vh_p[0], "SSLCertificateKeyFile", "/etc/ssl/private/ssl-cert-snakeoil.key")
        self.add_dir(vh_p[0], "Include", CONFIG_DIR + "options-ssl.conf")

        # Log actions and create save notes
        logger.info("Created an SSL vhost at %s" % ssl_fp)
        self.save_notes += 'Created ssl vhost at %s\n' % ssl_fp
        self.save("Making new ssl vhost at " + ssl_fp)
 
        # We know the length is one because of the assertion above
        ssl_vhost = self.__create_vhost(vh_p[0])
        self.vhosts.append(ssl_vhost)

        # Check if nonssl_vhost's address was NameVirtualHost
        # NOTE: Searches through Augeas seem to ruin changes to directives
        #       The configuration must also be saved before being searched
        #       for the new directives; For these reasons... this is tacked
        #       on after fully creating the new vhost
        # TODO: Figure out what to do for vhosts with multiple addresses
        if len(nonssl_vhost.addrs) == 1:
            if self.is_name_vhost(nonssl_vhost.addrs[0]) and not self.is_name_vhost(ssl_addrs[0]):
                self.add_name_vhost(ssl_addrs[0])
                logger.info("Enabling NameVirtualHosts on " + ssl_addrs[0])
                self.save("Added permanent NameVirtualHost for " + ssl_addrs[0])

        return ssl_vhost


    def redirect_all_ssl(self, ssl_vhost):
        """
        Adds Redirect directive to the port 80 equivalent of ssl_vhost
        First the function attempts to find the vhost with equivalent
        ip addresses that serves on non-ssl ports
        The function then adds the directive
        """
        general_v = self.__general_vhost(ssl_vhost)
        if general_v is None:
            #Add virtual_server with redirect
            logger.debug("Did not find http version of ssl virtual host... creating")
            return self.create_redirect_vhost(ssl_vhost)
        else:
            # Check if redirection already exists
            exists, code = self.existing_redirect(general_v)
            if exists:
                if code == 0:
                    logger.debug("Redirect already added")
                    return True, general_v
                else:
                    logger.debug("Unknown redirect exists for this vhost")
                    return False, general_v
            #Add directives to server
            self.add_dir(general_v.path, "RewriteEngine", "On")
            self.add_dir(general_v.path, "RewriteRule", REWRITE_HTTPS_ARGS)
            self.save_notes += 'Redirecting host in %s to ssl vhost in %s\n' % (general_v.file, ssl_vhost.file)
            self.save("Redirect all to ssl")
            return True, general_v

    def existing_redirect(self, vhost):
        """
        Checks to see if virtualhost already contains a rewrite or redirect
        returns boolean, integer
        The boolean indicates whether the redirection exists...
        The integer has the following code:
        0 - Existing trustify https rewrite rule is appropriate and in place
        1 - Virtual host contains a Redirect directive
        2 - Virtual host contains an unknown RewriteRule

        -1 is also returned in case of no redirection/rewrite directives
        """
        rewrite_path = self.find_directive("RewriteRule", None, vhost.path)
        redirect_path = self.find_directive("Redirect", None, vhost.path)

        if redirect_path:
            # "Existing Redirect directive for virtualhost"
            return True, 1
        if not rewrite_path:
            # "No existing redirection for virtualhost"
            return False, -1
        if len(rewrite_path) == len(REWRITE_HTTPS_ARGS):
            for idx, m in enumerate(rewrite_path):
                if self.aug.get(m) != REWRITE_HTTPS_ARGS[idx]:
                    # Not a trustify https rewrite
                    return True, 2
            # Existing trustify https rewrite rule is in place
            return True, 0
        # Rewrite path exists but is not a trustify https rule
        return True, 2
    
    def create_redirect_vhost(self, ssl_vhost):
        # Consider changing this to a dictionary check
        # Make sure adding the vhost will be safe
        conflict, hostOrAddrs = self.__conflicting_host(ssl_vhost)
        if conflict:
            return False, hostOrAddrs
        
        redirect_addrs = hostOrAddrs

        # get servernames and serveraliases
        serveralias = ""
        servername = ""
        size_n = len(ssl_vhost.names)
        if size_n > 0:
            servername = "ServerName " + ssl_vhost.names[0]
            if size_n > 1:
                serveralias = " ".join(ssl_vhost.names[1:size_n])
                serveralias = "ServerAlias " + serveralias
        redirect_file = "<VirtualHost" + redirect_addrs + "> \n\
" + servername + "\n\
" + serveralias + " \n\
ServerSignature Off \n\
\n\
RewriteEngine On \n\
RewriteRule ^.*$ https://%{SERVER_NAME}%{REQUEST_URI} [L,R=permanent]\n\
\n\
ErrorLog /var/log/apache2/redirect.error.log \n\
LogLevel warn \n\
</VirtualHost>\n"
        
        # Write out the file
        # This is the default name
        redirect_filename = "trustify-redirect.conf"

        # See if a more appropriate name can be applied
        if len(ssl_vhost.names) > 0:
            # Sanity check...
            # make sure servername doesn't exceed filename length restriction
            if ssl_vhost.names[0] < (255-23):
                redirect_filename = "trustify-redirect-" + ssl_vhost.names[0] + ".conf"
        # Write out file
        with open(SERVER_ROOT+"sites-available/"+redirect_filename, 'w') as f:
            f.write(redirect_file)
        logger.info("Created redirect file: " + redirect_filename)

        # -- Now update data structures to reflect the change --
        # Make sure that checkpoint data will 
        # remove the file if rollback is required
        self.new_files.append(redirect_filename)

        self.aug.load()
        # Make a new vhost data structure and add it to the lists
        new_fp = SERVER_ROOT + "sites-available/" + redirect_filename
        new_vhost = self.__create_vhost("/files" + new_fp)
        self.vhosts.append(new_vhost)
        
        # Finally create documentation for the change
        self.save_notes += 'Created a port 80 vhost, %s, for redirection to ssl vhost %s\n' % (new_vhost.file, ssl_vhost.file)

        return True, new_vhost
    
    def __conflicting_host(self, ssl_vhost):
        '''
        Checks for a conflicting host, such that a new port 80 host could not
        be created without ruining the apache config
        Used with redirection

        returns: conflict, hostOrAddrs - boolean
        if conflict: returns conflicting vhost
        if not conflict: returns space separated list of new host addrs
        '''
        # Consider changing this to a dictionary check
        redirect_addrs = ""
        for ssl_a in ssl_vhost.addrs:
            # Add space on each new addr, combine "VirtualHost"+redirect_addrs
            redirect_addrs = redirect_addrs + " "
            ssl_tup = ssl_a.partition(":")
            ssl_a_vhttp = ssl_tup[0] + ":80"
            # Search for a conflicting host...
            for v in self.vhosts:
                if v.enabled:
                    for a in v.addrs:
                        # Convert :* to standard ip address
                        if a.endswith(":*"):
                            a = a[:len(a)-2]
                        # Would require NameBasedVirtualHosts,too complicated?
                        # Maybe do later... right now just return false
                        # or overlapping addresses... order matters
                        if a == ssl_a_vhttp or a == ssl_tup[0]:
                            # We have found a conflicting host... just return
                            return True, v

            redirect_addrs = redirect_addrs + ssl_a_vhttp

        return False, redirect_addrs
        
    def __general_vhost(self, ssl_vhost):
        """
        Function needs to be throughly tested and perhaps improved
        Will not do well with malformed configurations
        Consider changing this into a dict check
        """
        # _default_:443 check
        # Instead... should look for vhost of the form *:80
        # Should we prompt the user?
        ssl_addrs = ssl_vhost.addrs
        if ssl_addrs == ["_default_:443"]:
            ssl_addrs = ["*:443"]
            
        for vh in self.vhosts:
            found = 0
            # Not the same vhost, and same number of addresses
            if vh != ssl_vhost and len(vh.addrs) == len(ssl_vhost.addrs):
                # Find each address in ssl_host in test_host
                for ssl_a in ssl_addrs:
                    ssl_tup = ssl_a.partition(":")
                    for test_a in vh.addrs:
                        test_tup = test_a.partition(":")
                        if test_tup[0] == ssl_tup[0]:
                            # Check if found...
                            if test_tup[2] == "80" or test_tup[2] == "" or test_tup[2] == "*":
                                found += 1
                                break
                # Check to make sure all addresses were found 
                # and names are equal
                if found == len(ssl_vhost.addrs) and set(vh.names) == set(ssl_vhost.names):
                    return vh
        return None

    def get_all_certs_keys(self):
        """
        Retrieve all certs and keys set in VirtualHosts on the Apache server
        returns: list of tuples with form [(cert, key)]
        """

        cert_key_pairs  = set()

        for vhost in self.vhosts:
            if vhost.ssl:
                cert_path = self.find_directive("SSLCertificateFile", None, vhost.path)
                key_path = self.find_directive("SSLCertificateKeyFile", None, vhost.path)
                # Can be removed once find directive can return ordered results
                if cert_path != 1 or key_path != 1:
                    logger.error("Too many cert or key directives in vhost %s" % vhost.file)
                    sys.exit(40)

                cert = os.path.abspath(self.aug.get(cert_path[0]))
                key = os.path.abspath(self.aug.get(key_path[0]))
                cert_key_pairs.add( (cert,key) )

        return cert_key_pairs

    def get_file_path(self, vhost_path):
        """
        Takes in Augeas path and returns the file name
        """

        # Strip off /files
        avail_fp = vhost_path[6:]
        # This can be optimized...
        while True:
            find_if = avail_fp.find("/IfModule")
            if  find_if != -1:
                avail_fp = avail_fp[:find_if]
                continue
            find_vh = avail_fp.find("/VirtualHost")
            if find_vh != -1:
                avail_fp = avail_fp[:find_vh]
                continue
            break
        return avail_fp
    
    def is_site_enabled(self, avail_fp):
        """
        Checks to see if the given site is enabled

        avail_fp:     string - Should be complete file path
        """
        enabled_dir = SERVER_ROOT + "sites-enabled/"
        for f in os.listdir(enabled_dir):
            if os.path.realpath(enabled_dir + f) == avail_fp:
                return True

        return False

    def enable_site(self, vhost):
        """
        Enables an available site, Apache restart required
        TODO: This function should number subdomains before the domain vhost
        """
        if "/sites-available/" in vhost.file:
            index = vhost.file.rfind("/")
            os.symlink(vhost.file, SERVER_ROOT + "sites-enabled/" + vhost.file[index:])
            vhost.enabled = True
            self.save_notes += 'Enabled site %s\n' % vhost.file
            return True
        return False
    
    def enable_mod(self, mod_name):
        """
        Enables mod_ssl
        """
        try:
	    # Use check_output so the command will finish before reloading      
            subprocess.check_call(["sudo", "a2enmod", mod_name], stdout=open("/dev/null", 'w'), stderr=open("/dev/null", 'w'))
            # Hopefully this waits for output                                   
            subprocess.check_call(["sudo", "/etc/init.d/apache2", "restart"], stdout=open("/dev/null", 'w'), stderr=open("/dev/null", 'w'))
        except:
	    logger.error("Error enabling mod_" + mod_name)
            sys.exit(1)

    def fnmatch_to_re(self, cleanFNmatch):
        """
        Method converts Apache's basic fnmatch to regular expression
        """
        regex = ""
        for letter in cleanFNmatch:
            if letter == '.':
                regex = regex + "\."
            elif letter == '*':
                regex = regex + ".*"
            # According to apache.org ? shouldn't appear
            # but in case it is valid...
            elif letter == '?':
                regex = regex + "."
            else:
                regex = regex + letter
        return regex

    def parse_file(self, file_path):
        """
        Checks to see if file_path is parsed by Augeas
        If file_path isn't parsed, the file is added and Augeas is reloaded
        """
        # Test if augeas included file for Httpd.lens
        # Note: This works for augeas globs, ie. *.conf
        incTest = self.aug.match("/augeas/load/Httpd/incl [. ='" + file_path + "']")
        if not incTest:
            # Load up files
            #self.httpd_incl.append(file_path)
            #self.aug.add_transform("Httpd.lns", self.httpd_incl, None, self.httpd_excl)
            self.__add_httpd_transform(file_path)
            self.aug.load()
    
    def save_apache_config(self):
        # Not currently used
        # Should be safe because it is a protected directory
        shutil.copytree(SERVER_ROOT, BACKUP_DIR + "apache2-" + str(time.time()))
    
    def recovery_routine(self):
        '''
        Revert all previously modified files. Set up log if it doesn't exist.
        '''
        if not os.path.isfile(MODIFIED_FILES):
            fd = open(MODIFIED_FILES, 'w')
            fd.close()
        else:
            fd = open(MODIFIED_FILES)
            files = fd.readlines()
            fd.close()
            if len(files) != 0:
                self.revert_config(files)

    def verify_dir_setup(self):
        '''
        Make sure that directories are setup with appropriate permissions
        Aim for defensive coding... make sure all input files 
        have permissions of root
        '''
        self.__make_or_verify_restricted_dir(CONFIG_DIR)
        self.__make_or_verify_restricted_dir(WORK_DIR)
        self.__make_or_verify_restricted_dir(BACKUP_DIR)

    def __make_or_verify_restricted_dir(self, directory, permissions=0755):
        if os.path.isdir(directory):
            if not self.__check_permissions(directory, permissions):
                logger.fatal(directory + " exists and does not contain the proper permissions or owner (root)")
                sys.exit(57)
        else:
            os.makedirs(directory, permissions)

    def __check_permissions(self, filepath, mode, uid=0):
        file_stat = os.stat(filepath)
        if stat.S_IMODE(file_stat.st_mode) != mode:
            return False
        return file_stat.st_uid == uid

    def standardize_excl(self):
        '''
        Standardize the excl arguments for the Httpd lens in Augeas
        Servers sometimes give incorrect defaults
        '''
        # attempt to protect against augeas error in 0.10.0 - ubuntu
        # *.augsave -> /*.augsave upon augeas.load()
        # Try to avoid bad httpd files
        # There has to be a better way... but after a day and a half of testing
        # I had no luck
        excl = ["*.augnew", "*.augsave", "*.dpkg-dist", "*.dpkg-bak", "*.dpkg-new", "*.dpkg-old", "*.rpmsave", "*.rpmnew", "*~", SERVER_ROOT + "*.augsave", SERVER_ROOT + "*~", SERVER_ROOT + "*/*augsave", SERVER_ROOT + "*/*~", SERVER_ROOT + "*/*/*.augsave", SERVER_ROOT + "*/*/*~"]
        
        for i in range(len(excl)):
            self.aug.set("/augeas/load/Httpd/excl[%d]" % (i+1), excl[i])

        self.aug.load()

    def revert_config(self, mod_files = None):
        """
        This function should reload the users original configuration files
        for all saves with reversible=True
        """
        if mod_files is None:
            try:
                mod_fd = open(MODIFIED_FILES, 'r')
                mod_files = mod_fd.readlines()
                mod_fd.close()
            except:
                logger.fatal("Error opening:", MODIFIED_FILES)
                sys.exit()
    
        try:
            for f in mod_files:
                shutil.copy2(f.rstrip() + ".augsave", f.rstrip())

            self.aug.load()
            # Clear file
            mod_fd = open(MODIFIED_FILES, 'w')
            mod_fd.close()
        except Exception as e:
            logger.fatal("Error reverting configuration")
            logger.fatal(e)
            sys.exit(36)

    def restart(self, quiet=False):
        """
        Restarts apache server
        """
        try:
            p = ''
            if quiet:
                p = subprocess.Popen(['/etc/init.d/apache2', 'restart'], stdout=subprocess.PIPE, stderr=open("/dev/null", 'w')).communicate()[0]
            else:
                p = subprocess.Popen(['/etc/init.d/apache2', 'restart'], stderr=subprocess.PIPE).communicate()[0]

            if "fail" in p:
                logger.error("Apache configuration is incorrect")
                logger.error(p)
                return False
            return True
        except:
            logger.fatal("Apache Restart Failed - Please Check the Configuration")
            sys.exit(1)

    def __add_httpd_transform(self, incl):
        """
        This function will correctly add a transform to augeas
        The existing augeas.add_transform in python is broken
        """
        lastInclude = self.aug.match("/augeas/load/Httpd/incl [last()]")
        self.aug.insert(lastInclude[0], "incl", False)
        self.aug.set("/augeas/load/Httpd/incl[last()]", incl)

    def configtest(self):
        p = subprocess.Popen(['sudo', '/usr/sbin/apache2ctl', 'configtest'], stdout=subprocess.PIPE, stderr=open("/dev/null", 'w')).communicate()[0]
        print p

    def save(self, mod_conf="Augeas Configuration", reversible=False):
        """
        Saves all changes to the configuration files
        Backups are stored as *.augsave files
        This function is not transactional
        TODO: Instead rely on challenge to backup all files before modifications
        
        mod_conf:   string - The title of the save.
        reversible: boolean - Indicates whether the changes made will be
                              quickly reversed in the future (challenges)
        """
        save_state = self.aug.get("/augeas/save")
        self.aug.set("/augeas/save", "noop")
        ex_errs = self.aug.match("/augeas//error")
        try:
            # This is a noop save
            self.aug.save()
        except:
            # Check for the root of save problems
            new_errs = self.aug.match("/augeas//error")
            logger.error("During Save - " + mod_conf)
            # Only print new errors caused by recent save
            for err in new_errs:
                if err not in ex_errs:
                    logger.error("Unable to save file - %s" % err[13:len(err)-6])
            logger.error("Attempted Save Notes")
            logger.error(self.save_notes)
            # Erase Save Notes
            self.save_notes = ""
            return False

        # Retrieve list of modified files
        # Note: Noop saves can cause the file to be listed twice, I used a 
        # set to remove this possibility. This is a known augeas error.
        save_paths = self.aug.match("/augeas/events/saved")

        # If the augeas tree didn't change, no files were saved and a backup
        # should not be created
        if save_paths:
            save_files = set()
            for p in save_paths:
                save_files.add(self.aug.get(p)[6:])

            valid, message = self.check_tempfile_saves(save_files, reversible)

            if not valid:
                logger.fatal(message)
                # What is the protocol in this situation?
                # This shouldn't happen if the challenge codebase is correct
                return False

            # Create Checkpoint
            if not reversible:
                self.create_checkpoint(save_files, mod_conf)

        self.aug.set("/augeas/save", save_state)
        self.save_notes = ""
        del self.new_files[:]
        self.aug.save()

        return True

    def create_checkpoint(self, save_files, mod_conf):
        cp_dir = BACKUP_DIR + str(time.time())
        try:
            #os.makedirs(BACKUP_DIR + datetime.date.today().strftime('%m-%y'))
            os.makedirs(cp_dir)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise
        #Update cp_dir for cleaner path creation
        cp_dir = cp_dir + "/"

        with open(cp_dir + "FILEPATHS", 'w') as op_fd:
            for idx, filename in enumerate(save_files):
                # Tag files with index so multiple files can have same basename
                logger.debug("Creating backup of %s" % filename)
                shutil.copy2(filename, cp_dir + os.path.basename(filename) + "_" + str(idx))
                op_fd.write(filename + '\n')

        with open(cp_dir + "CHANGES_SINCE", 'w') as notes_fd:
            notes_fd.write("-- %s --\n" % mod_conf)
            notes_fd.write(self.save_notes)

        # Mark any new files that have been created
        # The files will be deleted if the checkpoint is rolledback
        if self.new_files:
            with open(cp_dir + "NEW_FILES", 'w') as nf_fd:
                for filename in self.new_files:
                    nf_fd.write(filename + '\n')

    def recover_checkpoint(self, rollback = 1):
        # Sanity check input
        if type(rollback) is not int or rollbackrollback < 1:
            logger.error("Rollback argument must be a positive integer")
            return

        backups = os.listdir(BACKUP_DIR)
        backups.sort()

        if len(backups) < rollback:
            logger.error("Unable to rollback %d checkpoints, only %d exist" % (rollback, len(backups)))
        
        while rollback > 0 and backups:
            cp_dir = BACKUP_DIR + backups.pop()
            with open(cp_dir + "/FILEPATHS") as f:
                filepaths = f.read().splitlines()
                for idx, fp in enumerate(filepaths):
                    shutil.copy2(cp_dir + '/' + os.path.basename(fp) + '_' + str(idx), fp)
            try:
                # Remove any newly added files if they exist
                with open(cp_dir + "/NEW_FILES") as f:
                    filepaths = f.read().splitlines()
                    for fp in filepaths:
                        os.remove(fp)
            except:
                pass

            try:
                shutil.rmtree(cp_dir)
            except:
                logger.error("Unable to remove directory: %s" % cp_dir)
            rollback -= 1

        self.aug.load()

    def check_tempfile_saves(self, save_files, reversible):
        protected_fd = open(MODIFIED_FILES, 'r+')
        protected_files = protected_fd.read().splitlines()
        for filename in save_files:
            if filename in protected_files:
                protected_fd.close()
                return False, "Attempting to overwrite a reversible file - %s" %filename
        # No protected files are trying to be overwritten
        if reversible:
            for filename in save_files:
                protected_fd.write(filename + "\n")

        protected_fd.close()
        return True, "Successful"

    def display_checkpoints(self):
        backups = os.listdir(BACKUP_DIR)
        backups.sort(reverse=True)
        
        for bu in backups:
            print time.ctime(float(bu))
            with open(BACKUP_DIR + bu + "/CHANGES_SINCE") as f:
                print f.read()
            
            print "Affected files:"
            with open(BACKUP_DIR + bu + "/FILEPATHS") as f:
                filepaths = f.read().splitlines()
                for fp in filepaths:
                    print "  %s" % fp
            
            try:
                with open(cp_dir + "/NEW_FILES") as f:
                    print "New Configuration Files:"
                    filepaths = f.read().splitlines()
                    for fp in filepaths:
                        print "  %s" % fp
            except:
                pass
            print ""

def main():
    config = Configurator()
    logger.setLogger(logger.FileLogger(sys.stdout))
    logger.setLogLevel(logger.DEBUG)
    for v in config.vhosts:
        print v.file
        print v.addrs
        for name in v.names:
            print name

    """
    for m in config.find_directive("Listen", "443"):
        print "Directive Path:", m, "Value:", config.aug.get(m)

    for v in config.vhosts:
        for a in v.addrs:
            print "Address:",a, "- Is name vhost?", config.is_name_vhost(a)

    print config.get_all_names()
    """
    """
    test_file = "/home/james/Desktop/ports_test.conf"
    config.parse_file(test_file)

    config.aug.insert("/files" + test_file + "/IfModule[1]/arg", "directive", False)
    config.aug.set("/files" + test_file + "/IfModule[1]/directive[1]", "Listen")
    config.aug.set("/files" + test_file + "/IfModule[1]/directive[1]/arg", "556")
    config.aug.set("/files" + test_file + "/IfModule[1]/directive[2]", "Listen")
    config.aug.set("/files" + test_file + "/IfModule[1]/directive[2]/arg", "555")

    #config.save_notes = "Added listen 431 for test"
    #config.new_files.append("/home/james/Desktop/new_file.txt")
    #config.save("Testing Saves", False)
    #config.recover_checkpoint(1)
    """
    #config.display_checkpoints()
    config.configtest()
    """
    # Testing redirection and make_vhost_ssl
    ssl_vh = None
    for vh in config.vhosts:
        if not vh.addrs:
            print vh.names
            print vh.file
        if vh.addrs[0] == "23.20.47.131:80":
            print "Here we go"
            ssl_vh = config.make_vhost_ssl(vh)
            
    config.redirect_all_ssl(ssl_vh)
    """
    """
    for vh in config.vhosts:
        if len(vh.names) > 0:
            config.deploy_cert(vh, "/home/james/Documents/apache_choc/req.pem", "/home/james/Documents/apache_choc/key.pem", "/home/james/Downloads/sub.class1.server.ca.pem")
   """
    
if __name__ == "__main__":
    main()
