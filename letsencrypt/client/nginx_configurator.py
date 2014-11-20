from letsencrypt.client.CONFIG import SERVER_ROOT, BACKUP_DIR
from letsencrypt.client.CONFIG import REWRITE_HTTPS_ARGS, CONFIG_DIR, WORK_DIR
from letsencrypt.client.CONFIG import TEMP_CHECKPOINT_DIR, IN_PROGRESS_DIR
from letsencrypt.client.CONFIG import OPTIONS_SSL_CONF, LE_VHOST_EXT
from letsencrypt.client import logger, le_util, configurator


# This might be helpful... but feel free to use whatever you want
# class VH(object):
#     def __init__(self, filename_path, vh_path, vh_addrs, is_ssl, is_enabled):
#         self.file = filename_path
#         self.path = vh_path
#         self.addrs = vh_addrs
#         self.names = []
#         self.ssl = is_ssl
#         self.enabled = is_enabled

#     def set_names(self, listOfNames):
#         self.names = listOfNames

#     def add_name(self, name):
#         self.names.append(name)

class NginxConfigurator(AugeasConfigurator):
    
    def __init__(self, server_root=SERVER_ROOT):
        self.server_root = server_root

        # See if any temporary changes need to be recovered
        # This needs to occur before VH objects are setup...
        # because this will change the underlying configuration and potential
        # vhosts
        self.recovery_routine()
        # Check for errors in parsing files with Augeas
        # TODO - insert nginx lens info here???
        #self.check_parsing_errors("httpd.aug")
        

    def deploy_cert(self, vhost, cert, key, cert_chain=None):
        """
        Deploy cert in nginx
        """
        return

    def choose_virtual_host(self, name):
        """
        Chooses a virtual host based on the given domain name
        """
        return None

    def get_all_names(self):
        """
        Returns all names found in the nginx configuration
        """
        all_names = set()
        
        return all_names

        # Might be helpful... I know nothing about nginx lens
    # def get_include_path(self, cur_dir, arg):
    #     """
    #     Converts an Apache Include directive argument into an Augeas
    #     searchable path
    #     Returns path string
    #     """
    #     # Sanity check argument - maybe
    #     # Question: what can the attacker do with control over this string
    #     # Effect parse file... maybe exploit unknown errors in Augeas
    #     # If the attacker can Include anything though... and this function
    #     # only operates on Apache real config data... then the attacker has
    #     # already won.
    #     # Perhaps it is better to simply check the permissions on all
    #     # included files?
    #     # check_config to validate apache config doesn't work because it
    #     # would create a race condition between the check and this input

    #     # TODO: Fix this
    #     # Check to make sure only expected characters are used <- maybe remove
    #     # validChars = re.compile("[a-zA-Z0-9.*?_-/]*")
    #     # matchObj = validChars.match(arg)
    #     # if matchObj.group() != arg:
    #     #     logger.error("Error: Invalid regexp characters in %s" % arg)
    #     #     return []

    #     # Standardize the include argument based on server root
    #     if not arg.startswith("/"):
    #         arg = cur_dir + arg
    #     # conf/ is a special variable for ServerRoot in Apache
    #     elif arg.startswith("conf/"):
    #         arg = self.server_root + arg[5:]
    #     # TODO: Test if Apache allows ../ or ~/ for Includes

    #     # Attempts to add a transform to the file if one does not already exist
    #     self.parse_file(arg)

    #     # Argument represents an fnmatch regular expression, convert it
    #     # Split up the path and convert each into an Augeas accepted regex
    #     # then reassemble
    #     if "*" in arg or "?" in arg:
    #         postfix = ""
    #         splitArg = arg.split("/")
    #         for idx, split in enumerate(splitArg):
    #             # * and ? are the two special fnmatch characters
    #             if "*" in split or "?" in split:
    #                 # Turn it into a augeas regex
    #                 # TODO: Can this instead be an augeas glob instead of regex
    #                 splitArg[idx] = "* [label()=~regexp('%s')]" % self.fnmatch_to_re(split)
    #         # Reassemble the argument
    #         arg = "/".join(splitArg)

    #     # If the include is a directory, just return the directory as a file
    #     if arg.endswith("/"):
    #         return "/files" + arg[:len(arg)-1]
    #     return "/files"+arg

    
    def enable_redirect(self, ssl_vhost):
        """
        Adds Redirect directive to the port 80 equivalent of ssl_vhost
        First the function attempts to find the vhost with equivalent
        ip addresses that serves on non-ssl ports
        The function then adds the directive
        """
        return

    
    def enable_ocsp_stapling(self, ssl_vhost):
        return False

    def enable_hsts(self, ssl_vhost):
        return False

    def get_all_certs_keys(self):
        """
        Retrieve all certs and keys set in VirtualHosts on the Apache server
        returns: list of tuples with form [(cert, key, path)]
        """
        return None

    # Probably helpful reference
    # def get_file_path(self, vhost_path):
    #     """
    #     Takes in Augeas path and returns the file name
    #     """
    #     # Strip off /files
    #     avail_fp = vhost_path[6:]
    #     # This can be optimized...
    #     while True:
    #         # Cast both to lowercase to be case insensitive
    #         find_if = avail_fp.lower().find("/ifmodule")
    #         if  find_if != -1:
    #             avail_fp = avail_fp[:find_if]
    #             continue
    #         find_vh = avail_fp.lower().find("/virtualhost")
    #         if find_vh != -1:
    #             avail_fp = avail_fp[:find_vh]
    #             continue
    #         break
    #     return avail_fp

    def enable_site(self, vhost):
        """
        Enables an available site, Apache restart required
        """
        return False

        # Might be a usefule reference
    # def parse_file(self, file_path):
    #     """
    #     Checks to see if file_path is parsed by Augeas
    #     If file_path isn't parsed, the file is added and Augeas is reloaded
    #     """
    #     # Test if augeas included file for Httpd.lens
    #     # Note: This works for augeas globs, ie. *.conf
    #     incTest = self.aug.match("/augeas/load/Httpd/incl [. ='" + file_path + "']")
    #     if not incTest:
    #         # Load up files
    #         #self.httpd_incl.append(file_path)
    #         #self.aug.add_transform("Httpd.lns", self.httpd_incl, None, self.httpd_excl)
    #         self.__add_httpd_transform(file_path)
    #         self.aug.load()


    # Helpful reference?
    # def verify_setup(self):
    #     '''
    #     Make sure that files/directories are setup with appropriate permissions
    #     Aim for defensive coding... make sure all input files
    #     have permissions of root
    #     '''
    #     le_util.make_or_verify_dir(CONFIG_DIR, 0755)
    #     le_util.make_or_verify_dir(WORK_DIR, 0755)
    #     le_util.make_or_verify_dir(BACKUP_DIR, 0755)
    
    def restart(self, quiet=False):
        """
        Restarts nginx server
        """
        return

    # May be of use?
    # def __add_httpd_transform(self, incl):
    #     """
    #     This function will correctly add a transform to augeas
    #     The existing augeas.add_transform in python is broken
    #     """
    #     lastInclude = self.aug.match("/augeas/load/Httpd/incl [last()]")
    #     self.aug.insert(lastInclude[0], "incl", False)
    #     self.aug.set("/augeas/load/Httpd/incl[last()]", incl)

    def config_test(self):
        """ Check Configuration """
        return False




def main():
    return

if __name__ == "__main__":
    main()
