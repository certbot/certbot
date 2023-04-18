"""Internal Certbot display utilities."""
import sys
import textwrap
from typing import List
from typing import Optional

from acme import messages as acme_messages
from certbot.compat import misc


def wrap_lines(msg: str) -> str:
    """Format lines nicely to 80 chars.

    :param str msg: Original message

    :returns: Formatted message respecting newlines in message
    :rtype: str

    """
    lines = msg.splitlines()
    fixed_l = []

    for line in lines:
        fixed_l.append(textwrap.fill(
            line,
            80,
            break_long_words=False,
            break_on_hyphens=False))

    return '\n'.join(fixed_l)


def parens_around_char(label: str) -> str:
    """Place parens around first character of label.

    :param str label: Must contain at least one character

    """
    return "({first}){rest}".format(first=label[0], rest=label[1:])


def input_with_timeout(prompt: Optional[str] = None, timeout: float = 36000.0) -> str:
    """Get user input with a timeout.

    Behaves the same as the builtin input, however, an error is raised if
    a user doesn't answer after timeout seconds. The default timeout
    value was chosen to place it just under 12 hours for users following
    our advice and running Certbot twice a day.

    :param str prompt: prompt to provide for input
    :param float timeout: maximum number of seconds to wait for input

    :returns: user response
    :rtype: str

    :raises errors.Error if no answer is given before the timeout

    """
    # use of sys.stdin and sys.stdout to mimic the builtin input based on
    # https://github.com/python/cpython/blob/baf7bb30a02aabde260143136bdf5b3738a1d409/Lib/getpass.py#L129
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()

    line = misc.readline_with_timeout(timeout, prompt)

    if not line:
        raise EOFError
    return line.rstrip('\n')


def separate_list_input(input_: str) -> List[str]:
    """Separate a comma or space separated list.

    :param str input_: input from the user

    :returns: strings
    :rtype: list

    """
    no_commas = input_.replace(",", " ")
    # Each string is naturally unicode, this causes problems with M2Crypto SANs
    # TODO: check if above is still true when M2Crypto is gone ^
    return [str(string) for string in no_commas.split()]


def summarize_domain_list(domains: List[str]) -> str:
    """Summarizes a list of domains in the format of:
        example.com.com and N more domains
    or if there is are only two domains:
        example.com and www.example.com
    or if there is only one domain:
        example.com

    :param list domains: `str` list of domains
    :returns: the domain list summary
    :rtype: str
    """
    if not domains:
        return ""

    length = len(domains)
    if length == 1:
        return domains[0]
    elif length == 2:
        return " and ".join(domains)
    else:
        return "{0} and {1} more domains".format(domains[0], length-1)


def describe_acme_error(error: acme_messages.Error) -> str:
    """Returns a human-readable description of an RFC7807 error.

    :param error: The ACME error
    :returns: a string describing the error, suitable for human consumption.
    :rtype: str
    """
    parts = (error.title, error.detail)
    if any(parts):
        return ' :: '.join(part for part in parts if part is not None)
    if error.description:
        return error.description
    return error.typ
