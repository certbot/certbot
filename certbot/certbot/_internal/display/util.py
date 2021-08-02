"""Internal Certbot display utilities."""
import textwrap


def wrap_lines(msg):
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


def parens_around_char(label):
    """Place parens around first character of label.

    :param str label: Must contain at least one character

    """
    return "({first}){rest}".format(first=label[0], rest=label[1:])
