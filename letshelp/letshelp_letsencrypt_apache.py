#!/usr/bin/env python
"""Let's Encrypt Apache configuration submission script"""
import argparse
import os
import subprocess
import sys
import tempfile


DESCRIPTION = """
Let's Help is a simple script you can run to help out the Let's Encrypt
project. Since Let's Encrypt will support automatically configuring HTTPS on
many servers, we want to test this functionality on as many configurations as
possible. This script will create a sanitized copy of your Apache
configuration, notifying you of the files that have been selected. If (and only
if) you approve this selection, these files will be sent to the Let's Encrypt
developers. Of course, your submission will be encrypted.

"""

NO_APACHECTL = """
Unable to find `apachectl` which is required for this script to work. If it is
installed, please run this script again with the --apache-ctl command line
argument and path to the binary.

"""


def copy_config(server_root, temp_dir):
    """Safely copies server_root to temp_dir and returns copied files"""
    copied_files, copied_dirs = list(), list()
    dir_len = len(os.path.dirname(server_root))

    for config_path, config_dirs, config_files in os.walk(server_root):
        relative_path = config_path if not dir_len else config_path[dir_len+1:]
        temp_path = os.path.join(temp_dir, relative_path)
        os.mkdir(temp_path)

        copied_all = True
        copied_files_in_current_dir = list()
        for config_file in config_files:
            config_file_path = os.path.join(config_path, config_file)
            temp_file_path = os.path.join(temp_path, config_file)
            if os.path.islink(config_file_path):
                os.symlink(os.readlink(config_file_path), temp_file_path)
            elif _safe_config_file(config_file_path):
                _copy_file_without_comments(config_file_path, temp_file_path)
                copied_files_in_current_dir.append(config_file_path)
            else:
                copied_all = False

        # If copied all files in leaf directory
        if copied_all and not config_dirs:
            copied_dirs.append(config_path)
        else:
            copied_files += copied_files_in_current_dir

    return copied_files, copied_dirs


def _copy_file_without_comments(source, destination):
    """Copies source to destination, removing comments"""
    with open(source, "r") as infile:
        with open(destination, "w") as outfile:
            for line in infile:
                if not (line.isspace() or line.lstrip().startswith("#")):
                    outfile.write(line)


def _safe_config_file(config_file):
    """Returns True if config_file can be safely copied"""
    if "ASCII" in subprocess.check_output(["file", config_file]):
        if not config_file.endswith(".pem"):
            with open(config_file) as f:
                for line in f:
                    if line.startswith("-----BEGIN"):
                        return False
            return True

    return False


def setup_tempdir(args):
    """Creates a temporary directory and necessary files for config"""
    tempdir = tempfile.mkdtemp()

    with open(os.path.join(tempdir, "config_file"), "w") as f:
        f.write(args.config_file + "\n")

    with open(os.path.join(tempdir, "version"), "w") as f:
        f.write(subprocess.check_output([args.apache_ctl, "-v"]))

    with open(os.path.join(tempdir, "modules"), "w") as f:
        f.write(subprocess.check_output(
            [args.apache_ctl, "-d", args.server_root,
             "-f", args.config_file, "-M"]
        ))

    with open(os.path.join(tempdir, "vhosts"), "w") as f:
        f.write(subprocess.check_output(
            [args.apache_ctl, "-d", args.server_root, "-f",
             args.config_file, "-t", "-D", "DUMP_VHOSTS"]
        ))

    return tempdir


def verify_config(args):
    """Verifies server_root and config_file specify a valid config"""
    try:
        subprocess.check_call(
            [args.apache_ctl, "-d", args.server_root,
             "-f", args.config_file, "-t"]
        )
    except OSError:
        sys.exit(NO_APACHECTL)
    except subprocess.CalledProcessError:
        sys.exit("Syntax check from apachectl failed")


def locate_config(apache_ctl):
    """Uses the apachectl binary to find configuration files"""
    try:
        output = subprocess.check_output([apache_ctl, "-V"])
    except OSError:
        sys.exit(NO_APACHECTL)

    for line in output.splitlines():
        if "HTTPD_ROOT" in line:
            server_root = line[line.find("\"")+1:-1]
        elif "SERVER_CONFIG_FILE" in line:
            config_file = line[line.find("\"")+1:-1]

    if not (server_root and config_file):
        sys.exit(
            "Unable to locate Apache configuration. Please run this script "
            "again and specify --server-root and --config-file."
        )

    return server_root, config_file


def get_args():
    """Parses command line arguments"""
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "-c", "--apache-ctl", default="apachectl",
        help="path to the `apachectl` binary"
    )
    parser.add_argument(
        "-d", "--server-root",
        help="location of the root directory of your Apache configuration"
    )
    parser.add_argument(
        "-f", "--config-file",
        help="location of your main Apache configuration file"
    )
    args = parser.parse_args()

    # args.server_root XOR args.config_file
    if bool(args.server_root) != bool(args.config_file):
        sys.exit(
            "If either --server-root and --config-file are specified, they "
            "both must be included."
        )
    elif args.server_root and args.config_file:
        if args.config_file.startswith(args.server_root):
            args.config_file = args.config_file[len(args.server_root):]
        else:
            sys.exit(
                "This script expects the Apache configuration file to be "
                "inside the server root."
            )

    return args


def main():
    """Main script execution"""
    args = get_args()
    if not args.server_root:
        args.server_root, args.config_file = locate_config(args.apache_ctl)

    verify_config(args)
    tempdir = setup_tempdir(args)
    files, dirs = copy_config(args.server_root, tempdir)
    print "Copied these files:"
    for f in files:
        print f
    print "Copied all files in these directories:"
    for d in dirs:
        print d


if __name__ == "__main__":
    main()
