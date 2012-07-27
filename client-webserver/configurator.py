import augeas
import subprocess
import re

BASE_DIR = "/etc/apache2/"

class VH(object):
    def __init__(self, vh_path, vh_addrs):
        self.path = vh_path
        self.addrs = vh_addrs
        self.names = []

    def set_names(self, listOfNames):
        self.names = listOfNames

    def add_name(self, name):
        self.names.append(name)

class Configurator(object):
    
    def __init__(self):
        self.hasSSLServer = False
        self.isModSSLLoaded = False
        # TODO: this instantiation can be optimized to only load Httd 
        #       relevant files
        # Set Augeas flags to save backup
        self.aug = augeas.Augeas(None, None, 1 << 0)
        self.vhosts = []
        # httpd_files - All parsable Httpd files
        # add_transform overwrites all currently loaded files so we must 
        # maintain state
        self.httpd_files = []
        for m in self.aug.match("/augeas/load/Httpd/incl"):
            self.httpd_files.append(self.aug.get(m))

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
        """
        search = {}
        path = {}
        search["cert_file"] = "//* [self::directive='SSLCertificateFile'][last()]/arg"
        search["cert_key"] = "//*[self::directive='SSLCertificateKeyFile'][last()]/arg"
        
        path["cert_file"] = self.aug.match(vhost.path + search["cert_file"])
        path["cert_key"] = self.aug.match(vhost.path + search["cert_key"])

        # Only include if a certificate chain is specified
        if cert_chain is not None:
            search["cert_chain"] = "//*[self::directive='SSLCertificateChainFile'][last()]/arg"
            path["cert_chain"] = self.aug.match(vhost.path + search["cert_chain"])

            includeArgs = self.aug.match(vhost.path + "//*[self::directive='Include']/arg")
        for k in path.iterkeys():
            if len(path[k]) == 0:
                # Directive not found... search the includes
                # Search in reverse because it is the last directive that 
                # matters
                for includeArg in reversed(includeArgs):  
                    path[k] = self.search_include(includeArg, search[k])
                    if len(path[k]) > 0:
                        break
        
        for k in path.iterkeys():
            if len(path[k]) == 0:
                # Throw some "can't find all of the directives error"
                print "DEBUG - Error: cannot find ", search[k]
                print "DEBUG - in ", vhost.path
                print "VirtualHost was not modified"
                # Presumably break here so that the virtualhost is not modified
                return

        # Testing printout
        #for k in path.iterkeys():
        #    print self.aug.get(path[k][0])
            
        self.aug.set(path["cert_file"][0], cert)
        self.aug.set(path["cert_key"][0], key)
        if cert_chain is not None:
            self.aug.set(path["cert_chain"][0], cert_chain)
        
        # Testing printout
        #for k in path.iterkeys():
        #    print "Changed: ", path[k][0]
        #    print self.aug.get(path[k][0])
        
        self.aug.save()

    def add_servernames(self, host):
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
        #Search sites-available, httpd.conf for possible virtual hosts
        paths = self.aug.match("/files" + BASE_DIR + "sites-available//VirtualHost")
        for p in paths:
            addrs = []
            args = self.aug.match(p + "/*")
            for arg in args:
                addrs.append(self.aug.get(arg))
            self.vhosts.append(VH(p, addrs))

        for host in self.vhosts:
            self.add_servernames(host)

        return self.vhosts

    def is_name_vhost(self, addr):
        # search for NameVirtualHost directive for ip_addr
        # check httpd.conf, ports.conf, 
        # note ip_addr can be FQDN
        paths = self.aug.match("/files" + BASE_DIR + "/*[self::directive=NameVirtualHost']/arg")
        name_vh = []
        for p in paths:
            name_vh.append(self.aug.get(p))
        
        # TODO: Should be reviewed for efficiency/completeness
        # TODO: Check ramifications for FQDN/IP_ADDR mismatch overlap
        #       ie. NameVirtualHost FQDN ... <VirtualHost IPADDR>
        #       Does adding additional NameVirtualHost directives cause problems
        # TODO: Test matching
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
        TODO: For final code... this function should check that ports.conf
              is included along the main path... it is by default
        """
        aug_file_path = "/files" + BASE_DIR + "ports.conf"
        # Some testing code
        #self.aug.add_transform("Httpd.lns", BASE_DIR+"ports_test.conf")
        #self.aug.load()
        ifMods = self.aug.match(aug_file_path + "/IfModule/*[self::arg='mod_ssl.c']")

        # No IfModule mod_ssl.c in ports.conf... create one
        if len(ifMods) == 0:
            self.append_ifmod(aug_file_path, "mod_ssl.c")
            ifMods = self.aug.match(aug_file_path + "/IfModule/*[self::arg='mod_ssl.c']")

        # Get first mod_ssl IfMod from main tree and strip arg from it
        # Three because 'arg'
        ifModPath = ifMods[0][:len(ifMods[0]) - 3]
        # IfModule can have only one valid argument, so append after
        self.aug.insert(ifMods[0], "directive", False)
        nvhPath = ifModPath + "directive[1]"
        self.aug.set(nvhPath, "NameVirtualHost")
        self.aug.set(nvhPath + "/arg", addr)

        # testing printout
        #file = self.aug.match(aug_file_path + "//*")
        #for p in file:
            #print p, self.aug.get(p)

        self.aug.save()

    def append_ifmod(self, aug_conf_path, mod):
        #print "No " + mod + " IfModule section... creating!"
        self.aug.set(aug_conf_path + "/IfModule[last() + 1]", "")
        self.aug.set(aug_conf_path + "/IfModule[last()]/arg", mod)
        
    def find_directive(self, directive, arg, start="/files"+BASE_DIR+"apache2.conf"):
        """
        Recursively searches through config files to find directives
        TODO: arg should probably be a list
        TODO: Allow unknown args
        """
        matches = self.aug.match(start + "//* [self::directive='"+directive+"']/* [self::arg='" + arg + "']")
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
            arg = BASE_DIR + arg[5:]
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
        Checks apachectl to get loaded module list
        """
        try:
            p = subprocess.check_output(["sudo", "apache2ctl", "-M"], stderr=open("/dev/null"))
        except:
            print "Error accessing apache2ctl for loaded modules!"
            return False
        if "ssl_module" in p:
            return True
        return False

    # Go down the Include rabbit hole
    # TODO: REMOVE... use find_directive
    def search_include(self, includeArg, searchStr):
        print "Deprecated Function... please use find_directive"
        # Standardize the include argument based on server root
        arg = includeArg
        if not includeArg.startswith("/"):
            arg = BASE_DIR + includeArg

        # Test if augeas included file for Httpd.lens
        incTest = aug.match("/files" + arg + "/*")
        if len(incTest) == 0:
            # Load up file
            self.aug.add_transform("Httpd.lns", arg)
            self.aug.load()
            
        return self.aug.match("/files" + arg + searchStr)

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
        # Test if augeas included file for Httpd.lens
        # Note: This works for augeas globs, ie. *.conf
        incTest = self.aug.match("/augeas/load/Httpd/incl [. ='" + file_path + "']")
        if len(incTest) == 0:
            # Load up files
            self.httpd_files.append(file_path)
            self.aug.add_transform("Httpd.lns", self.httpd_files)
            self.aug.load()

def recurmatch(aug, path):
    if path:
        if path != "/":
            val = aug.get(path)
            if val:
                yield (path, val)

        for i in aug.match(path + "/*"):
            for x in recurmatch(aug, i):
                yield x

def main():
    config = Configurator()
    config.get_virtual_hosts()
    for v in config.vhosts:
        for name in v.names:
            print name

    for m in config.find_directive("Listen", "443"):
        print "Directive Path:", m, "Value:", config.aug.get(m)

    #for m in config.aug.match("/augeas/load/Httpd/incl"):
    #    print m, config.aug.get(m)
    #config.add_name_vhost("example2.com:443")
    #for vh in config.vhosts:
        #if len(vh.names) > 0:
            #config.deploy_cert(vh, "/home/james/Documents/apache_choc/default.crt", "/home/james/Documents/apache_choc/testing.key")

#print config.search_include("/etc/apache2/choc_sni_cert_chal_test.conf", "/*")

if __name__ == "__main__":
    main()

    
