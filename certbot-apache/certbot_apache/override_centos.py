""" Distribution specific overrides for CentOS family (RHEL/Fedora/CentOS """
class Override(object):
    """CentOS override class"""
    def __init__(self, config):
        """
        Initializes the override class.

        :param config: caller `certbot_apache.configurator.ApacheConfigurator`
        """
        self.config = config
