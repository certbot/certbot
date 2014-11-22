import logger
import textwrap
import time

import dialog

from letsencrypt.client import display


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
        msg = "%s [%s] %s" % (self.timefmt(), self.debugLevel(level), data)
        wm = textwrap.fill(msg, 80)
        self.outfile.write("%s\n" % wm)


class NcursesLogger(Logger):

    def __init__(self,
                 firstmessage="",
                 height = display.HEIGHT,
                 width = display.WIDTH - 4):
        self.lines = []
        self.all_content = ""
        self.d = dialog.Dialog()
        self.height = height
        self.width = width
        self.add(firstmessage)

    '''
    Only show the last (self.height) lines;
    note that lines can wrap at self.width, so
    a single line could actually be multiple lines
    '''
    def add(self, s):
        self.all_content += s

        for line in s.splitlines():
            # check for lines that would wrap
            cur_out = line
            while len(cur_out) > self.width:

                # find first space before self.width chars into cur_out
                last_space_pos = cur_out.rfind(' ', 0, self.width)

                if (last_space_pos == -1):
                    # no spaces, just cut them off at whatever
                    self.lines.append(cur_out[0:self.width])
                    cur_out = cur_out[self.width:]
                else:
                    # cut off at last space
                    self.lines.append(cur_out[0:last_space_pos])
                    cur_out = cur_out[last_space_pos+1:]
            if cur_out != '':
                self.lines.append(cur_out)


        # show last 16 lines
        self.content = '\n'.join(self.lines[-self.height:])
        self.show()

    def show(self):
        # add the padding around the box
        self.d.infobox(self.content, self.height+2, self.width+4)

    def log(self, level, data):
        self.add(str(data) + "\n")

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

    # Set the logging type you want to use (stdout logging):
    #logger.setLogger(FileLogger(sys.stdout))
    setLogger(NcursesLogger())

    # Set the most verbose you want to log (TRACE, DEBUG, INFO, WARN, ERROR, FATAL, NONE)
    setLogLevel(logger.TRACE)

    # Log a message:
    #logger.log(logger.INFO, "logger!")

    time.sleep(0.01)
    info("This is a long line, it's pretty long, butitalso hasbig wordsthat areprobably hardtobreak oninan easywayforthe ncurseslib, sowhatdoes itdo then?")
    info("aa " + "a"*70 + "B")

    for i in range(20):
        info("iteration #%d/20" % i)
        time.sleep(0.3)


    # Alternatively, use
    error("errrrr")

    trace("some trace data: %d - %f - %s" % (5, 8.3, 'cows'))
