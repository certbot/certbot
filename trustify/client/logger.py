
import sys
import time


class Singleton(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(
                                cls, *args, **kwargs)
        return cls._instance

# log levels
TRACE=5
DEBUG=4
INFO=3
WARN=2
ERROR=1
FATAL=0
NONE=-1

class Logger(Singleton):
    debugLevelStr = {TRACE:'TRACE', DEBUG:'DEBUG', INFO:'INFO', \
                     WARN:'WARN', ERROR:'ERROR', FATAL:'FATAL'}

    def __init__(self):
        self.level = INFO

    def debugLevel(self, level=DEBUG):
        return self.debugLevelStr[level]

    def log(self, level, data):
        raise Exception("Error: no Logger defined")

    def timefmt(self, t=None):
        if t == None:
            t = time.time()
        return time.strftime("%b %d %Y %H:%M:%S", time.localtime(t)) + ('%.03f' % (t - int(t)))[1:]


class FileLogger(Logger):
    def __init__(self, outfile):
        self.outfile = outfile


    def log(self, level, data):
        msg = "%s [%s] %s\n" % (self.timefmt(), self.debugLevel(level), data)
        self.outfile.write(msg)

import dialog
class NcursesLogger(Logger):

    def __init__(self, firstmessage="", height=18, width=70):
        self.content = firstmessage
        self.d = dialog.Dialog()
        self.height = height
        self.width = width
        self.show()

    def add(self, s):
        self.content += s
        self.show()

    def show(self):
        self.d.infobox(self.content, self.height, self.width)

    def log(self, level, data):
        self.add(data + "\n")

log_instance = None

def setLogger(log_inst):
    global log_instance
    log_instance = log_inst
    
def setLogLevel(log_level):
    global log_instance
    log_instance.level = log_level

def log(level, data):
    global log_instance
    if level <= log_instance.level:
        log_instance.log(level, data)

def trace(data):
    log(TRACE, data)

def debug(data):
    log(DEBUG, data)

def info(data):
    log(INFO, data)

def warn(data):
    log(WARN, data)

def error(data):
    log(ERROR, data)

def fatal(data):
    log(FATAL, data)

def none(data):
    # Uh...what?
    pass 

if __name__ == "__main__":
    # Unit test/example usage:
    import logger

    # Set the logging type you want to use (stdout logging):
    #logger.setLogger(FileLogger(sys.stdout))
    logger.setLogger(NcursesLogger())

    # Set the most verbose you want to log (TRACE, DEBUG, INFO, WARN, ERROR, FATAL, NONE)
    logger.setLogLevel(logger.TRACE)

    # Log a message:
    logger.log(logger.INFO, "logger!")

    time.sleep(0.01)

    # Alternatively, use 
    logger.error("errrrr")

    logger.trace("some trace data: %d - %f - %s" % (5, 8.3, 'cows'))





