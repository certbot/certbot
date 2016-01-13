from sys import argv, stderr


def main():
    """Act like letsencrypt --version insofar as printing the version number to
    stderr."""
    if '--version' in argv:
        stderr.write('letsencrypt 99.9.9\n')
