"""Classes that wrap the postconf command line utility.
"""
import six
from certbot import errors
from certbot_postfix import util


class ConfigMain(util.PostfixUtilBase):
    """A parser for Postfix's main.cf file."""


    def __init__(self, executable, config_dir=None):
        super(ConfigMain, self).__init__(executable, config_dir)
        self._db = {}
        # List of current master.cf overrides from Postfix config. Dictionary
        # of parameter name => list of tuples (service name, paramter value)
        # Note: We should never modify master without explicit permission.
        self._master_db = {}
        self._updated = {}
        self._read_from_conf()
        # TODO (sydneyli): Document the above fields in future documentation commit.

    def _read_from_conf(self):
        """Reads initial parameter state from main.cf
        """
        out = self._get_output()
        for name, value in _parse_main_output(out):
            self._db[name] = value
        out = self._get_output_master()
        for name, value in _parse_main_output(out):
            service, param_name = name.rsplit("/", 1)
            if param_name not in self._master_db:
                self._master_db[param_name] = []
            self._master_db[param_name].append((service, value))

    def _get_output_master(self):
        return self._get_output('-P')

    def get_default(self, name):
        """Retrieves default value of parameter `name` from postfix parameters.
            :param str name: The name of the parameter to fetch.
            :rtype str: The default value of parameter `name`.
        """
        out = self._get_output(['-d', name])
        _, value = next(_parse_main_output(out), (None, None))
        return value

    def get(self, name):
        """Retrieves working value of parameter `name` from postfix parameters.
            :param str name: The name of the parameter to fetch.
            :rtype str: The value of parameter `name`.
        """
        if name in self._updated:
            return self._updated[name]
        return self._db[name]

    def get_master_overrides(self, name):
        """Retrieves list of overrides for parameter `name` in postfix's Master config
        file.
            :returns: List of tuples (service, value), meaning that parameter `name`
                      is overridden as `value` for `service`.
            :rtype `list` of `tuple` of `str:
        """
        if name in self._master_db:
            return self._master_db[name]
        return None

    def set(self, name, value, check_override=None):
        """Sets parameter `name` to `value`.
        If `name` is overridden by a particular service in `master.cf`, calls
        `check_override` on `name`, and the set of overrides.

        Note that this function does not flush these parameter values to main.cf;
        To do that, use `flush`.
            :param str name: The name of the parameter to set.
            :param str value: The value of the parameter.
        """
        if name not in self._db:
            raise KeyError("Parameter name %s is not a valid Postfix parameter name.", name)
        # Check to see if this parameter is overridden by master.
        overrides = self.get_master_overrides(name)
        if check_override is not None and overrides is not None:
            check_override(name, overrides)
        if value != self._db[name]:
        # _db contains the "original" state of parameters. We only care about
        # writes if they cause a delta from the original state.
            self._updated[name] = value
        elif name in self._updated:
        # If this write reverts a previously updated parameter back to the
        # original DB's state, we don't have to keep track of it in _updated.
            del self._updated[name]

    def flush(self):
        """Flushes all parameter changes made using "self.set" to "main.cf".
            :raises error.PluginError: When we can't flush to main.cf.
        """
        if len(self._updated) == 0:
            return
        args = ['-e']
        for name, value in six.iteritems(self._updated):
            args.append('{0}={1}'.format(name, value))
        try:
            self._get_output(args)
        except:
            raise errors.PluginError("Unable to save to Postfix config!")
        for name, value in six.iteritems(self._updated):
            self._db[name] = value
        self._updated = {}

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


