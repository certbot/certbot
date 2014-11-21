class Validator(object):
    """Configuration validator."""

    def redirect(self, name):
        raise NotImplementedError()

    def ocsp_stapling(self, name):
        raise NotImplementedError()

    def https(self, names):
        raise NotImplementedError()

    def hsts(self, name):
        raise NotImplementedError()
