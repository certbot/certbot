"""Classes that wrap the postconf command line utility.
"""
import collections

from certbot import errors
from certbot_postfix import util


class ConfigMain(util.PostfixUtilBase):
    """A parser for Postfix's main.cf file."""

    _modifiers = None
    _db = None
    _updated = {}
    """An iterable containing additional CLI flags for postconf."""

    def __init__(self, executable, config_dir=None):
        util.PostfixUtilBase.__init__(self, executable, config_dir)
        self._db = {}
        # List of current master.cf overrides from Postfix config. Dictionary
        # of parameter name => list of tuples (service name, paramter value)
        # Note: We should never modify master without explicit permission.
        self._master_db = {}
        self._read_from_conf()

    def _read_from_conf(self):
        """Reads initial parameter state from main.cf
        """
        out = self._get_output()
        for name, value in _parse_main_output(out):
            if not value:
                value = ""
            self._db[name] = value
        out = self._get_output('-P') # get master parameters
        for name, value in _parse_main_output(out):
            service, param_name = name.rsplit("/")
            if not value:
                value = ""
            if param_name not in _master_db:
                self._master_db[param_name] = []
            self._master_db[param_name].append( (service, value) )

    def get_default(self, name):
        """Retrieves default value of parameter |name| from postfix parameters.
            :param str name: The name of the parameter to fetch.
            :rtype str: The default value of parameter |name|.
        """
        out = self._get_output(['-d', name])
        _, value = next(_parse_main_output(out), (None, None))
        return value

    def get(self, name):
        """Retrieves working value of parameter |name| from postfix parameters.
            :param str name: The name of the parameter to fetch.
            :rtype str: The value of parameter |name|.
        """
        if name in self._updated:
            return self._updated[name]
        return self._db[name]
    
    def get_master_overrides(self, name):
        """Retrieves list of overrides for parameter |name| in postfix's Master config
        file. 
            :returns: List of tuples (service, value), meaning that parameter |name|
                      is overridden as |value| for |service|.
            :rtype `list` of `tuple` of `str: 
        """
        if name in self._master_db:
            return self._master_db[name]
        return None

    def set(self, name, value, check_override=None):
        """Sets parameter |name| to |value|.
        If |name| is overridden by a particular service in `master.cf`, calls
        `check_override` on |name|, and the set of overrides.

        Note that this function does not flush these parameter values to main.cf;
        To do that, use |flush|.
            :param str name: The name of the parameter to set.
            :param str value: The value of the parameter.
        """
        if name not in self._db:
            return # TODO: error here
        # Check to see if this parameter is overridden by master.
        overrides = self.get_master_overrides(name)
        if check_override is not None and overrides is not None:
            check_override(name, overrides)
        # We've updated this name before.
        if name in self._updated:
            if value == self._updated[name]:
                return
            if value == self._db[name]:
                del self._updated[name]
                return
        # We haven't updated this name before.
        else:
            # If we're just setting the default value, ignore.
            if value != self._db[name]:
                self._updated[name] = value

    def flush(self):
        """Flushes all parameter changes made using "self.set" to "main.cf".
            :raises error.PluginError: When we can't flush to main.cf.
        """
        if len(self._updated) == 0:
            return
        args = ['-e']
        for name, value in self._updated.iteritems():
            args.append('{0}={1}'.format(name, value))
        #TODO (sydli) bugfix: Reset _updated after flushing :)
        try:
            self._get_output(args)
        except:
            raise errors.PluginError("Unable to save to Postfix config!")
        for name, value in self._updated.iteritems():
            self._db[name] = value
        self._updated = {}

    def _call(self, extra_args=None):
        """Runs Postconf and returns the result.

        If self._modifiers is set, it is provided on the command line to
        postconf before any values in extra_args.

        :param list extra_args: additional arguments for the command

        :returns: data written to stdout and stderr
        :rtype: `tuple` of `str`

        :raises subprocess.CalledProcessError: if the command fails

        """
        all_extra_args = []
        for args_list in (self._modifiers, extra_args,):
            if args_list is not None:
                all_extra_args.extend(args_list)

        return super(ConfigMain, self)._call(all_extra_args)

def _parse_main_output(output):
    """Parses the raw output from Postconf about main.cf.
    Expects the output to look like:

    name1 = value1
    name2 = value2

    :param str output: data postconf wrote to stdout about main.cf

    :returns: generator providing key-value pairs from main.cf
    :rtype: generator

    """
    for line in output.splitlines():
        name, _, value = line.partition(" =")
        yield name, value.strip()


