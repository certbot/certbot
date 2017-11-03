"""Classes that wrap the postconf command line utility.

These classes allow you to interact with a Postfix config like it is a
dictionary, with the getting and setting of values in the config being
handled automatically by the class.

"""
import collections

from certbot_postfix import util


class ReadOnlyMainMap(util.PostfixUtilBase, collections.Mapping):
    """A read-only view of a Postfix main.cf file."""

    _modifiers = None
    """An iterable containing additional CLI flags for postconf."""

    def __getitem__(self, name):
        return next(_parse_main_output(self._get_output([name])))[1]

    def __iter__(self):
        for name, _ in _parse_main_output(self._get_output()):
            yield name

    def __len__(self):
        return sum(1 for _ in _parse_main_output(self._get_output()))

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

        return super(ReadOnlyMainMap, self)._call(all_extra_args)


def _parse_main_output(output):
    """Parses the raw output from Postconf about main.cf.

    :param str output: data postconf wrote to stdout about main.cf

    :returns: generator providing key-value pairs from main.cf
    :rtype: generator

    """
    for line in output.splitlines():
        name, _, value = line.partition(" =")
        yield name, value.split()
