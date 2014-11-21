class Challenge(object):

    def __init__(self, configurator):
        self.config = configurator

    def perform(self, quiet=True):
        raise NotImplementedError()

    def generate_response(self):
        raise NotImplementedError()

    def cleanup(self):
        raise NotImplementedError()
