""" Use demandimport to postpone actually loading a module until it is
    first used.  This will decrease start-up time a lot, as most imported
    modules are not used at all --- however, some third-party modules
    might cause problems as some `ImportError's aren't raised immediately. """

import os
import sys
import demandimport

def enable():
    """ Configures and enables on-demand module importing. """
    if sys.version_info < (2, 7):
        return # demandimport isn't reliable on Python <2.7
    if os.environ.get('LETSENCRYPT_NO_DEMANDIMPORT'):
        return

    demandimport.enable()

    demandimport.ignore('PyICU')      # parsedatetime
    demandimport.ignore('simplejson') # requests.compat
