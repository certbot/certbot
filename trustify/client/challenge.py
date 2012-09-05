from trustify.client import logger

class Challenge(object):
    def __init__(self, configurator):
        self.config = configurator
    def perform(self):
        logger.error("Error - base class challenge.perform()")
    def clean(self):
        logger.error("Error - base class challenge.clean()")
    
