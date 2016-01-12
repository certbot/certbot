from sys import argv, stderr


def main():
    """Act like letsencrypt --version insofar as printing the version number to
    stderr."""
    if len(argv) >= 2 and argv[1] == '--version':
        stderr.write('letsencrypt 99.9.9\n')
