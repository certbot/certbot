""" Registry and decorator for override classes """
OVERRIDE_CLASSES = {}

def register(distros):
    """ Decorator function that will register distro based override class

    :param distros: `list` of distribution IDs that can be found from
        variable ID or LIKE in /etc/os-release
    """
    def register_distro(caller):
        """ Inner decorator function to create override class dict entry """
        for distro in distros:
            OVERRIDE_CLASSES[distro] = caller
        return caller
    return register_distro
