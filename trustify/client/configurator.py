import augeas
import subprocess
import re
import os
import sys
import socket

from trustify.client.CONFIG import SERVER_ROOT

#TODO - Stop Augeas from loading up backup emacs files in sites-available

class VH(object):
    def __init__(self, filename_path, vh_path, vh_addrs):
        self.file = filename_path
        self.path = vh_path
        self.addrs = vh_addrs
        self.names = []

    def set_names(self, listOfNames):
        self.names = listOfNames

    def add_name(self, name):
        self.names.append(name)

class Configurator(object):
    
    def __init__(self):
        # TODO: this instantiation can be optimized to only load Httd 
        #       relevant files
        # Set Augeas flags to save backup
        self.aug = augeas.Augeas(None, None, 1 << 0)
        self.vhosts = self.get_virtual_hosts()
        # httpd_files - All parsable Httpd files
        # add_transform overwrites all currently loaded files so we must 
        # maintain state
        self.httpd_files = []
        for m in self.aug.match("/augeas/load/Httpd/incl"):
            self.httpd_files.append(self.aug.get(m))
        self.mod_files = set()
        # Add name_server association dict
        self.assoc = dict()

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
        TODO: Should add/remove chain directives
        TODO: Make sure last directive is changed
        """
        search = {}
        path = {}
        
        path["cert_file"] = self.find_directive("SSLCertificateFile", None, vhost.path)
        path["cert_key"] = self.find_directive("SSLCertificateKeyFile", None, vhost.path)

        # Only include if a certificate chain is specified
        if cert_chain is not None:
            path["cert_chain"] = self.find_directive("SSLCertificateChainFile", None, vhost.path)
        
        for k in path.iterkeys():
            if len(path[k]) == 0:
                # Throw some "can't find all of the directives error"
                print "DEBUG - Error: cannot find ", search[k]
                print "DEBUG - in ", vhost.path
                print "VirtualHost was not modified"
                # Presumably break here so that the virtualhost is not modified
                return False
        
        #print "Deploying Certificate to VirtualHost"
            
        self.aug.set(path["cert_file"][0], cert)
        self.aug.set(path["cert_key"][0], key)
        if cert_chain is not None:
            self.aug.set(path["cert_chain"][0], cert_chain)
        
        return self.save("Virtual Server - deploying certificate")

    def choose_virtual_host(self, name, ssl=True):
        """
        Chooses a virtual host based on the given domain name

        returns: VH object
        TODO: This should return vhost of :443 if both 80 and 443 exist
              This is currently just a very basic demo version
        """
        # TODO: TEST
        for dn, vh in self.assoc:
            if dn == name:
                return vh
        # Check for servernames/aliases
        for v in self.vhosts:
            for n in v.names:
                # TODO: Or a converted FQDN address
                if n == name:
                    return v
        for v in self.vhosts:
            for a in v.addrs:
                tup = a.partition(":")
                if tup[0] == name and tup[2] == "443":
                    return v
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
        all_names = []
        for v in self.vhosts:
            all_names.extend(v.names)
            for a in v.addrs:
                a_tup = a.partition(":")
                try:
                    socket.inet_aton(a_tup[0])
                    all_names.append(socket.gethostbyaddr(a_tup[0])[0])
                except (socket.error, socket.herror, socket.timeout):
                    continue

        return all_names

    def __add_servernames(self, host):
        """
        Helper function for get_virtual_hosts()
        """
        # This is case sensitive, but Apache is case insensitve
        # Spent a bunch of time trying to get case insensitive search
        # it should be possible as of .7 with /i or 'append i' but I have been
        # unsuccessful thus far
        nameMatch = self.aug.match(host.path + "//*[self::directive=~regexp('[sS]erver[nN]ame')] | " + host.path + "//*[self::directive=~regexp('[sS]erver[aA]lias')]")
        for name in nameMatch:
            args = self.aug.match(name + "/*")
            for arg in args:
                host.add_name(self.aug.get(arg))
                

    def get_virtual_hosts(self):
        """
        Returns list of virtual hosts found in the Apache configuration
        """
        #Search sites-available, httpd.conf for possible virtual hosts
        paths = self.aug.match("/files" + SERVER_ROOT + "sites-available//VirtualHost")
        vhs = []
        for p in paths:
            addrs = []
            args = self.aug.match(p + "/arg")
            for arg in args:
                addrs.append(self.aug.get(arg))
            vhs.append(VH(self.get_file_path(p), p, addrs))

        for host in vhs:
            self.__add_servernames(host)

        return vhs

    def is_name_vhost(self, addr):
        """
        Checks if addr has a NameVirtualHost directive in the Apache config
        addr:    string
        """
        # search for NameVirtualHost directive for ip_addr
        # check httpd.conf, ports.conf, 
        # note ip_addr can be FQDN
        paths = self.find_directive("NameVirtualHost", None)
        name_vh = []
        for p in paths:
            name_vh.append(self.aug.get(p))
        
        # TODO: Check ramifications for FQDN/IP_ADDR mismatch overlap
        #       ie. NameVirtualHost FQDN ... <VirtualHost IPADDR>
        #       Does adding additional NameVirtualHost directives cause problems
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
        Directive is added to ports.conf unless 
        """
        aug_file_path = "/files" + SERVER_ROOT + "ports.conf"
        self.add_dir_to_ifmodssl(aug_file_path, "NameVirtualHost", addr)
        
        if len(self.find_directive("NameVirtualHost", addr)) == 0:
            print "ports.conf is not included in your Apache config... "
            print "Adding NameVirtualHost directive to httpd.conf"
            self.add_dir_to_ifmodssl("/files" + SERVER_ROOT + "httpd.conf", "NameVirtualHost", addr)
            

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
            print "Please load the SSL module with Apache"
            return False

        # Check for Listen 443
        # TODO: This could be made to also look for ip:443 combo
        # TODO: Need to search only open directives and IfMod mod_ssl.c
        if len(self.find_directive("Listen", "443")) == 0:
            print self.find_directive("Listen", "443")
            print "Setting the Apache Server to Listen on port 443"
            self.add_dir_to_ifmodssl("/files" + SERVER_ROOT + "ports.conf", "Listen", "443")

        # Check for NameVirtualHost
        # First see if any of the vhost addresses is a _default_ addr
        for addr in vhost.addrs:
            tup = addr.partition(":") 
            if tup[0] == "_default_":
                if not self.is_name_vhost(default_addr):
                    #print "Setting all VirtualHosts on " + default_addr + " to be name based virtual hosts"
                    self.add_name_vhost(default_addr)
                return True
        # No default addresses... so set each one individually
        for addr in vhost.addrs:
            if not self.is_name_vhost(addr):
                #print "Setting VirtualHost at", addr, "to be a name based virtual host"
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
                        print "Error: Invalid regexp characters in", arg
                        return []
                    # Turn it into a augeas regex
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
            p = subprocess.check_output(["sudo", "/usr/sbin/apache2ctl", "-M"], stderr=open("/dev/null", 'w'))
        except:
            print "Error accessing apache2ctl for loaded modules!"
            print "This may be caused by an Apache Configuration Error"
            return False
        if "ssl_module" in p:
            return True
        return False

    def make_vhost_ssl(self, avail_fp):
        """
        Duplicates vhost and adds default ssl options
        New vhost will reside as (avail_fp)-ssl
        If original vhost is currently enabled, ssl-vhost will be enabled
        """
        # TODO TEST
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
        self.aug.load()

        # change address to address:443, address:80
        ssl_addr_p = self.aug.match("/files"+ssl_fp+"//VirtualHost/arg")
        avail_addr_p = self.aug.match("/files"+avail_fp+"//VirtualHost/arg")
        for i in range(avail_addr_p):
            avail_old_arg = self.aug.get(avail_addr_p[i])
            ssl_old_arg = self.aug.get(ssl_addr_p[i])
            avail_tup = avail_old_arg.partition(":")
            ssl_tup = ssl_old_arg.partition(":")
            self.aug.set(avail_addr_p[i], avail_tup[0] + ":80")
            self.aug.set(ssl_addr_p[i], ssl_tup[0] + ":443")

        # Add directives
        vh_p = self.aug.match("/files"+ssl_fp+"//VirtualHost")
        if len(vh_p) != 1:
            print "Error: should only be one vhost in", avail_fp
            sys.exit(1)

        self.add_dir(vh_p[0], "SSLCertificateFile", "/etc/ssl/certs/ssl-cert-snakeoil.pem")
        self.add_dir(vh_p[0], "SSLCertificateKeyFile", "/etc/ssl/private/ssl-cert-snakeoil.key")
        self.add_dir(vh_p[0], "Include", CONFIG_DIR + "options-ssl.conf")
        # reload configurator vhosts
        self.vhosts = self.get_virtual_hosts()

        # TODO: At some point site should be enabled
        return

    def redirect_all_ssl(self, ssl_vhost, domains):
        """
        Adds Redirect directive to the port 80 equivalent of ssl_vhost
        First the function attempts to find the vhost with equivalent
        ip addresses that serves on non-ssl ports
        The function then adds the directive
        
        I did not use mod rewrite because it can be confusing for the admin.
        The rewrite can be placed anywhere and the admin might not be aware 
        or remember the location.  Also, the rewrite rule would have to play
        nicely with the existing admin's rules. It is difficult to determine
        the exact results of the other rules and order matters.
        
        TODO: If port 80 vhost doesn't exist, add one to the same ssl_host 
        file with the redirect
        """
        general_v = self.__general_vhost(ssl_vhost)
        if general_v is None:
            #Add virtual_server with redirect
            print "Did not find general_ssl server"
            print "This function isn't implemented yet"
            return False
        else:
            #Add directives to server
            for d in domains:
                self.add_dir(general_v.path, "Redirect", ["permanent", "/", "https://" + d + "/"])
        self.aug.save("Redirect all to ssl")
        return True
        
    def __general_vhost(self, ssl_vhost):
        """
        Function needs to be throughly tested and perhaps improved
        Will not do well with malformed configurations
        """
        for vh in self.vhosts:
            found = 0
            # Not the same vhost, and same number of addresses
            if vh != ssl_vhost and len(vh.addrs) == len(ssl_vhost.addrs):
                # Find each address in ssl_host in test_host
                for ssl_a in ssl_vhost.addrs:
                    ssl_tup = ssl_a.partition(":")
                    for test_a in vh.addrs:
                        test_tup = test_a.partition(":")
                        if test_tup[0] == ssl_tup[0]:
                            # Sanity check TODO: is * a problem?
                            if test_tup[2] == "80":
                                found += 1
                                break
                if found == len(ssl_vhost.addrs):
                    return vh
        return None

    def get_file_path(self, vhost_path):
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

    def enable_site(self, avail_fp):
        """
        Enables an available site, Apache restart required
        TODO: This function should number subdomains before the domain vhost
        """
        if "/sites-available/" in avail_fp:
            index = avail_fp.rfind("/")
            os.symlink(avail_fp, SERVER_ROOT + "sites-enabled/" + avail_fp[index:])
            return True
        return False
    
    def enable_mod_ssl(self):
        """
        Enables mod_ssl
        TODO: TEST
        """
        # Use check_output so the command will finish before reloading
        subprocess.check_output(["sudo", "a2enmod", "ssl"], stderr=open("/dev/null", 'w'))
        subprocess.call(["sudo", "/etc/init.d/apache2", "reload"], stdout=open("/dev/null", 'w'))

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
        if len(incTest) == 0:
            # Load up files
            self.httpd_files.append(file_path)
            self.aug.add_transform("Httpd.lns", self.httpd_files)
            self.aug.load()

    def save(self, mod_conf="Augeas Configuration", reversible=False):
        """
        Saves all changes to the configuration files
        Backups are stored as *.augsave files
        
        mod_conf:   string - Error message presented in case of problem
                             useful for debugging
        reversible: boolean - Indicates whether the changes made will be
                              reversed in the future
        """
        try:
            self.aug.save()
            # Retrieve list of modified files
            save_paths = self.aug.match("/augeas/events/saved")
            for path in save_paths:
                # Strip off /files
                filename = self.aug.get(path)[6:]
                if filename in self.mod_files:
                    # Output a warning... hopefully this can be avoided so more
                    # complex code doesn't have to be written
                    print "Reversible file has been overwritten -", filename
                    sys.exit(37)
                if reversible:
                    self.mod_files.add(filename)
            return True
        except IOError:
            print "Unable to save file - ", mod_conf
            print "Is the script running as root?"
        return False

    def revert_config(self):
        """
        This function should reload the users original configuration files
        for all saves with reversible=True
        """
        for f in self.mod_files:
            #print "reverting", f
            os.rename(f + ".augsave", f)
        self.aug.load()
        self.mod_files.clear()
        

def main():
    config = Configurator()
    for v in config.vhosts:
        print v.file
        print v.addrs
        for name in v.names:
            print name

    for m in config.find_directive("Listen", "443"):
        print "Directive Path:", m, "Value:", config.aug.get(m)

    for v in config.vhosts:
        for a in v.addrs:
            print "Address:",a, "- Is name vhost?", config.is_name_vhost(a)

    print config.get_all_names()

    config.parse_file("/etc/apache2/ports_test.conf")
    #config.make_vhost_ssl("/etc/apache2/sites-available/default")
    """
    # Testing redirection
    for vh in config.vhosts:
        if vh.addrs[0] == "*:443":
            print "Here we go"
            print vh.path
            config.redirect_all_ssl(vh, ["localhost"])
    config.save()
    """
    """
    for vh in config.vhosts:
        if len(vh.names) > 0:
            config.deploy_cert(vh, "/home/james/Documents/apache_choc/req.pem", "/home/james/Documents/apache_choc/key.pem")
    """

if __name__ == "__main__":
    main()

    
