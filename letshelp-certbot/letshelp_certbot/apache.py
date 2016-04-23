#!/usr/bin/env python
"""Certbot Apache configuration submission script"""

from __future__ import print_function

import argparse
import atexit
import contextlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap


_DESCRIPTION = """
Let's Help is a simple script you can run to help out the Certbot
project. Since Certbot will support automatically configuring HTTPS on
many servers, we want to test this functionality on as many configurations as
possible. This script will create a sanitized copy of your Apache
configuration, notifying you of the files that have been selected. If (and only
if) you approve this selection, these files will be sent to the Certbot
developers.

"""


_NO_APACHECTL = """
Unable to find `apachectl` which is required for this script to work. If it is
installed, please run this script again with the --apache-ctl command line
argument and the path to the binary.

"""


# Keywords likely to be found in filenames of sensitive files
_SENSITIVE_FILENAME_REGEX = re.compile(r"^(?!.*proxy_fdpass).*pass.*$|private|"
                                       r"secret|^(?!.*certbot).*cert.*$|crt|"
                                       r"key|rsa|dsa|pw|\.pem|\.der|\.p12|"
                                       r"\.pfx|\.p7b")


def make_and_verify_selection(server_root, temp_dir):
    """Copies server_root to temp_dir and verifies selection with the user

    :param str server_root: Path to the Apache server root
    :param str temp_dir: Path to the temporary directory to copy files to

    """
    copied_files, copied_dirs = copy_config(server_root, temp_dir)

    print(textwrap.fill("A secure copy of the files that have been selected "
                        "for submission has been created under {0}. All "
                        "comments have been removed and the files are only "
                        "accessible by the current user. A list of the files "
                        "that have been included is shown below. Please make "
                        "sure that this selection does not contain private "
                        "keys, passwords, or any other sensitive "
                        "information.".format(temp_dir)))
    print("\nFiles:")
    for copied_file in copied_files:
        print(copied_file)
    print("Directories (including all contained files):")
    for copied_dir in copied_dirs:
        print(copied_dir)

    sys.stdout.write("\nIs it safe to submit these files? ")
    while True:
        ans = raw_input("(Y)es/(N)o: ").lower()
        if ans.startswith("y"):
            return
        elif ans.startswith("n"):
            sys.exit("Your files were not submitted")


def copy_config(server_root, temp_dir):
    """Safely copies server_root to temp_dir and returns copied files

    :param str server_root: Absolute path to the Apache server root
    :param str temp_dir: Path to the temporary directory to copy files to

    :returns: List of copied files and a list of leaf directories where
        all contained files were copied
    :rtype: `tuple` of `list` of `str`

    """
    copied_files, copied_dirs = [], []
    dir_len = len(os.path.dirname(server_root))

    for config_path, config_dirs, config_files in os.walk(server_root):
        temp_path = os.path.join(temp_dir, config_path[dir_len + 1:])
        os.mkdir(temp_path)

        copied_all = True
        copied_files_in_current_dir = []
        for config_file in config_files:
            config_file_path = os.path.join(config_path, config_file)
            temp_file_path = os.path.join(temp_path, config_file)
            if os.path.islink(config_file_path):
                os.symlink(os.readlink(config_file_path), temp_file_path)
            elif safe_config_file(config_file_path):
                copy_file_without_comments(config_file_path, temp_file_path)
                copied_files_in_current_dir.append(config_file_path)
            else:
                copied_all = False

        # If copied all files in leaf directory
        if copied_all and not config_dirs:
            copied_dirs.append(config_path)
        else:
            copied_files += copied_files_in_current_dir

    return copied_files, copied_dirs


def copy_file_without_comments(source, destination):
    """Copies source to destination, removing comments

    :param str source: Path to the file to be copied
    :param str destination: Path where source should be copied to

    """
    with open(source, "r") as infile:
        with open(destination, "w") as outfile:
            for line in infile:
                if not (line.isspace() or line.lstrip().startswith("#")):
                    outfile.write(line)


def safe_config_file(config_file):
    """Returns True if config_file can be safely copied

    :param str config_file: Path to an Apache configuration file

    :returns: True if config_file can be safely copied
    :rtype: bool

    """
    config_file_lower = config_file.lower()
    if _SENSITIVE_FILENAME_REGEX.search(config_file_lower):
        return False

    proc = subprocess.Popen(["file", config_file],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    file_output, _ = proc.communicate()

    if "ASCII" in file_output:
        possible_password_file = empty_or_all_comments = True
        with open(config_file) as config_fd:
            for line in config_fd:
                if not (line.isspace() or line.lstrip().startswith("#")):
                    empty_or_all_comments = False
                    if line.startswith("-----BEGIN"):
                        return False
                    elif ":" not in line:
                        possible_password_file = False
        # If file isn't empty or commented out and could be a password file,
        # don't include it in selection. It is safe to include the file if
        # it consists solely of comments because comments are removed before
        # submission.
        return empty_or_all_comments or not possible_password_file

    return False


def setup_tempdir(args):
    """Creates a temporary directory and necessary files for config

    :param argparse.Namespace args: Parsed command line arguments

    :returns: Path to temporary directory
    :rtype: str

    """
    tempdir = tempfile.mkdtemp()

    with open(os.path.join(tempdir, "config_file"), "w") as config_fd:
        config_fd.write(args.config_file + "\n")

    proc = subprocess.Popen([args.apache_ctl, "-v"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(os.path.join(tempdir, "version"), "w") as version_fd:
        version_fd.write(proc.communicate()[0])

    proc = subprocess.Popen([args.apache_ctl, "-d", args.server_root, "-f",
                             args.config_file, "-M"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(os.path.join(tempdir, "modules"), "w") as modules_fd:
        modules_fd.write(proc.communicate()[0])

    proc = subprocess.Popen([args.apache_ctl, "-d", args.server_root, "-f",
                             args.config_file, "-t", "-D", "DUMP_VHOSTS"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(os.path.join(tempdir, "vhosts"), "w") as vhosts_fd:
        vhosts_fd.write(proc.communicate()[0])

    return tempdir


def verify_config(args):
    """Verifies server_root and config_file specify a valid config

    :param argparse.Namespace args: Parsed command line arguments

    """
    with open(os.devnull, "w") as devnull:
        try:
            subprocess.check_call([args.apache_ctl, "-d", args.server_root,
                                   "-f", args.config_file, "-t"],
                                  stdout=devnull, stderr=subprocess.STDOUT)
        except OSError:
            sys.exit(_NO_APACHECTL)
        except subprocess.CalledProcessError:
            sys.exit("Syntax check from apachectl failed")


def locate_config(apache_ctl):
    """Uses the apachectl binary to find configuration files

    :param str apache_ctl: Path to `apachectl` binary


    :returns: Path to Apache server root and main configuration file
    :rtype: `tuple` of `str`

    """
    try:
        proc = subprocess.Popen([apache_ctl, "-V"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = proc.communicate()
    except OSError:
        sys.exit(_NO_APACHECTL)

    server_root = config_file = ""
    for line in output.splitlines():
        # Relevant output lines are of the form: -D DIRECTIVE="VALUE"
        if "HTTPD_ROOT" in line:
            server_root = line[line.find('"') + 1:-1]
        elif "SERVER_CONFIG_FILE" in line:
            config_file = line[line.find('"') + 1:-1]

    if not (server_root and config_file):
        sys.exit("Unable to locate Apache configuration. Please run this "
                 "script again and specify --server-root and --config-file")

    return server_root, config_file


def get_args():
    """Parses command line arguments

    :returns: Parsed command line options
    :rtype: argparse.Namespace

    """
    parser = argparse.ArgumentParser(description=_DESCRIPTION)
    parser.add_argument("-c", "--apache-ctl", default="apachectl",
                        help="path to the `apachectl` binary")
    parser.add_argument("-d", "--server-root",
                        help=("location of the root directory of your Apache "
                              "configuration"))
    parser.add_argument("-f", "--config-file",
                        help=("location of your main Apache configuration "
                              "file relative to the server root"))
    args = parser.parse_args()

    # args.server_root XOR args.config_file
    if bool(args.server_root) != bool(args.config_file):
        sys.exit("If either --server-root and --config-file are specified, "
                 "they both must be included")
    elif args.server_root and args.config_file:
        args.server_root = os.path.abspath(args.server_root)
        args.config_file = os.path.abspath(args.config_file)

        if args.config_file.startswith(args.server_root):
            args.config_file = args.config_file[len(args.server_root) + 1:]
        else:
            sys.exit("This script expects the Apache configuration file to be "
                     "inside the server root")

    return args


def main():
    """Main script execution"""
    args = get_args()
    if args.server_root is None:
        args.server_root, args.config_file = locate_config(args.apache_ctl)

    verify_config(args)
    tempdir = setup_tempdir(args)
    atexit.register(lambda: shutil.rmtree(tempdir))
    make_and_verify_selection(args.server_root, tempdir)

    tarpath = os.path.join(tempdir, "config.tar.gz")
    # contextlib.closing used for py26 support
    with contextlib.closing(tarfile.open(tarpath, mode="w:gz")) as tar:
        tar.add(tempdir, arcname=".")

    # TODO: Submit tarpath


if __name__ == "__main__":
    main()  # pragma: no cover
