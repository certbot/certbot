from letsencrypt.client import logger
#import logger

class Challenge(object):
    def __init__(self, configurator):
        self.config = configurator
    def perform(self, quiet=True):
        logger.error("Error - base class challenge.perform()")
    def generate_response(self):
        logger.error("Error - base class challenge.generate_response()")
    def clean(self):
        logger.error("Error - base class challenge.clean()")

