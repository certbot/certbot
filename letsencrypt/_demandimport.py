""" Use demandimport to postpone actually loading a module until it is
    first used.  This will decrease start-up time a lot, as most imported
    modules are not used at all --- however, some third-party modules
    might cause problems as some `ImportError's aren't raised immediately. """

import demandimport
demandimport.enable()

demandimport.ignore('PyICU')
