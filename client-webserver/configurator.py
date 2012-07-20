import augeas

# Important note... aug.match is by default case sensitive
# Apache configs are not case sensitive.  It may be necessary to use our
# own recursive matcher (recurmatch()) to search for directives.

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
        # TODO: this instantiation can be optimized to only load Httd relevant files
        # Set Augeas flags to save backup
        self.aug = augeas.Augeas(None, None, 1 << 0)
        self.vhosts = []

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
        nameMatch = self.aug.match(host.path + "//*[self::directive='ServerName'] | " + host.path + "//*[self::directive='ServerAlias']")
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
        paths = self.aug.match("/files" + BASE_DIR + "/*[self::directive=NameVirtualHost']")
        name_vh = []
        for p in paths:
            name_vh.append(self.aug.match(p + "/arg[1]"))
        
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

    def add_name_vhost(self, vhost):
        """
        TODO: Should add directive to httpd.conf
        """
        return

    def check_ssl_loaded(self):
        """
        TODO: Should check apache2 -M to see if mod_ssl is currently loaded
        """
        return

    # Go down the Include rabbit hole
    # TODO: Test various forms of Include, ie. /*.conf, directories
    def search_include(self, includeArg, searchStr):
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

    def recurmatch(path):
        if path:
            if path != "/":
                val = self.aug.get(path)
                if val:
                    yield (path, val)

            for i in self.aug.match(path + "/*"):
                for x in recurmatch(i):
                    yield x

def main():
    config = Configurator()
    config.get_virtual_hosts()
    for vh in config.vhosts:
        if len(vh.names) > 0:
            config.deploy_cert(vh, "/home/james/Documents/apache_choc/default.crt", "/home/james/Documents/apache_choc/testing.key")

#print config.search_include("/etc/apache2/choc_sni_cert_chal_test.conf", "/*")

if __name__ == "__main__":
    main()

    
