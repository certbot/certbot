Overview
~~~~~~~~

Applications with more than a handful of user-settable options are best
configured through a combination of command line args, config files,
hard-coded defaults, and in some cases, environment variables.

Python's command line parsing modules such as argparse have very limited
support for config files and environment variables, so this module
extends argparse to add these features.

Available on PyPI: http://pypi.python.org/pypi/ConfigArgParse

.. image:: https://travis-ci.org/bw2/ConfigArgParse.svg?branch=master
    :target: https://travis-ci.org/bw2/ConfigArgParse

Features
~~~~~~~~

-  command-line, config file, env var, and default settings can now be
   defined, documented, and parsed in one go using a single API (if a
   value is specified in more than one way then: command line >
   environment variables > config file values > defaults)
-  config files can have .ini or .yaml style syntax (eg. key=value or
   key: value)
-  user can provide a config file via a normal-looking command line arg
   (eg. -c path/to/config.txt) rather than the argparse-style @config.txt
-  one or more default config file paths can be specified
   (eg. ['/etc/bla.conf', '~/.my_config'] )
-  all argparse functionality is fully supported, so this module can
   serve as a drop-in replacement (verified by argparse unittests).
-  env vars and config file keys & syntax are automatically documented
   in the -h help message
-  new method :code:`print_values()` can report keys & values and where
   they were set (eg. command line, env var, config file, or default).
-  lite-weight (no 3rd-party library dependencies except (optionally) PyYAML)
-  extensible (:code:`ConfigFileParser` can be subclassed to define a new
   config file format)
-  unittested by running the unittests that came with argparse but on
   configargparse, and using tox to test with python2.7+ and python3+

Example
~~~~~~~

*my_script.py*:

Script that defines 4 options and a positional arg and then parses and prints the values. Also,
it prints out the help message as well as the string produced by :code:`format_values()` to show
what they look like.

.. code:: py

   import configargparse

   p = configargparse.ArgParser(default_config_files=['/etc/app/conf.d/*.conf', '~/.my_settings'])
   p.add('-c', '--my-config', required=True, is_config_file=True, help='config file path')
   p.add('--genome', required=True, help='path to genome file')  # this option can be set in a config file because it starts with '--'
   p.add('-v', help='verbose', action='store_true')
   p.add('-d', '--dbsnp', help='known variants .vcf', env_var='DBSNP_PATH')  # this option can be set in a config file because it starts with '--'
   p.add('vcf', nargs='+', help='variant file(s)')

   options = p.parse_args()

   print(options)
   print("----------")
   print(p.format_help())
   print("----------")
   print(p.format_values())    # useful for logging where different settings came from


*config.txt:*

Since the script above set the config file as required=True, lets create a config file to give it:

.. code:: py

    # settings for my_script.py
    genome = HCMV     # cytomegalovirus genome
    dbsnp = /data/dbsnp/variants.vcf


*command line:*

Now run the script and pass it the config file:

.. code:: bash

    python my_script.py --genome hg19 --my-config config.txt  f1.vcf  f2.vcf

*output:*

Here is the result:

.. code:: bash

    Namespace(dbsnp='/data/dbsnp/variants.vcf', genome='hg19', my_config='config.txt', vcf=['f1.vcf', 'f2.vcf'], verbose=False)
    ----------
    usage: my_script.py [-h] --genome GENOME [-v] -c MY_CONFIG [-d DBSNP]
                        vcf [vcf ...]
    Args that start with '--' (eg. --genome) can also be set in a config file
    (/etc/settings.ini or /home/jeff/.my_settings or provided via -c) by using
    .ini or .yaml-style syntax (eg. genome=value). Command-line values override
    environment variables which override config file values which override
    defaults.

    positional arguments:
      vcf                   variant file
    optional arguments:
      -h, --help            show this help message and exit
      --genome GENOME       path to genome file
      -v                    verbose
      -c MY_CONFIG, --my-config MY_CONFIG
                            config file path
      -d DBSNP, --dbsnp DBSNP
                            known variants .vcf [env var: DBSNP_PATH]
    ----------
    Command Line Args:   --genome hg19 --my-config config.txt f1.vcf f2.vcf
    Config File (config.txt):
      dbsnp:             /data/dbsnp/variants.vcf

Special Values
~~~~~~~~~~~~~~

Under the hood, configargparse handles environment variables and config file
values by converting them to their corresponding command line arg. For
example, "key = value" will be processed as if "--key value" was specified
on the command line.

Also, the following special values (whether in a config file or an environment
variable) are handled in a special way to support booleans and lists:

-  :code:`key = true` is handled as if "--key" was specified on the command line.
   In your python code this key must be defined as a boolean flag
   (eg. action="store_true" or similar).

-  :code:`key = [value1, value2, ...]` is handled as if "--key value1 --key value2"
   etc. was specified on the command line. In your python code this key must
   be defined as a list (eg. action="append").

Config File Syntax
~~~~~~~~~~~~~~~~~~

Only command line args that have a long version (eg. one that starts with '--')
can be set in a config file. For example, "--color" can be set by
putting "color=green" in a config file. The config file syntax depends on the
constuctor arg: :code:`config_file_parser_class` which can be set to one of the
provided classes: :code:`DefaultConfigFileParser` or :code:`YAMLConfigFileParser`,
or to your own subclass of the :code:`ConfigFileParser` abstract class.

*DefaultConfigFileParser*  - the full range of valid syntax is:

.. code:: yaml

        # this is a comment
        ; this is also a comment (.ini style)
        ---            # lines that start with --- are ignored (yaml style)
        -------------------
        [section]      # .ini-style section names are treated as comments

        # how to specify a key-value pair (all of these are equivalent):
        name value     # key is case sensitive: "Name" isn't "name"
        name = value   # (.ini style)  (white space is ignored, so name = value same as name=value)
        name: value    # (yaml style)
        --name value   # (argparse style)

        # how to set a flag arg (eg. arg which has action="store_true")
        --name
        name
        name = True    # "True" and "true" are the same

        # how to specify a list arg (eg. arg which has action="append")
        fruit = [apple, orange, lemon]
        indexes = [1, 12, 35 , 40]


*YAMLConfigFileParser*  - allows a subset of YAML syntax (http://goo.gl/VgT2DU)

.. code:: yaml

        # a comment
        name1: value
        name2: true    # "True" and "true" are the same

        fruit: [apple, orange, lemon]
        indexes: [1, 12, 35, 40]


ArgParser Singletons
~~~~~~~~~~~~~~~~~~~~~~~~~

To make it easier to configure different modules in an application,
configargparse provides globally-available ArgumentParser instances
via configargparse.get_argument_parser('name') (similar to
logging.getLogger('name')).

Here is an example of an application with a utils module that also
defines and retrieves its own command-line args.

*main.py*

.. code:: py

    import configargparse
    import utils

    p = configargparse.get_argument_parser()
    p.add_argument("-x", help="Main module setting")
    p.add_argument("--m-setting", help="Main module setting")
    options = p.parse_known_args()   # using p.parse_args() here may raise errors.

*utils.py*

.. code:: py

    import configargparse
    p = configargparse.get_argument_parser()
    p.add_argument("--utils-setting", help="Config-file-settable option for utils")

    if __name__ == "__main__":
       options = p.parse_known_args()

Help Formatters
~~~~~~~~~~~~~~~

:code:`ArgumentDefaultsRawHelpFormatter` is a new HelpFormatter that both adds
default values AND disables line-wrapping. It can be passed to the constructor:
:code:`ArgParser(.., formatter_class=ArgumentDefaultsRawHelpFormatter)`


Aliases
~~~~~~~

The configargparse.ArgumentParser API inherits its class and method
names from argparse and also provides the following shorter names for
convenience:

-  p = configargparse.get_arg_parser()  # get global singleton instance
-  p = configargparse.get_parser()
-  p = configargparse.ArgParser()  # create a new instance
-  p = configargparse.Parser()
-  p.add_arg(..)
-  p.add(..)
-  options = p.parse(..)

HelpFormatters:

- RawFormatter = RawDescriptionHelpFormatter
- DefaultsFormatter = ArgumentDefaultsHelpFormatter
- DefaultsRawFormatter = ArgumentDefaultsRawHelpFormatter


Design Notes
~~~~~~~~~~~~

Unit tests:

tests/test_configargparse.py contains custom unittests for features
specific to this module (such as config file and env-var support), as
well as a hook to load and run argparse unittests (see the built-in
test.test_argparse module) but on configargparse in place of argparse.
This ensures that configargparse will work as a drop in replacement for
argparse in all usecases.

Previously existing modules (PyPI search keywords: config argparse):

-  argparse (built-in module python v2.7+ )

   -  Good:

      -  fully featured command line parsing
      -  can read args from files using an easy to understand mechanism

   -  Bad:

      -  syntax for specifying config file path is unusual (eg.
         @file.txt)and not described in the user help message.
      -  default config file syntax doesn't support comments and is
         unintuitive (eg. --namevalue)
      -  no support for environment variables

-  ConfArgParse v1.0.15
   (https://pypi.python.org/pypi/ConfArgParse)

   -  Good:

      -  extends argparse with support for config files parsed by
         ConfigParser
      -  clear documentation in README

   -  Bad:

      -  config file values are processed using
         ArgumentParser.set_defaults(..) which means "required" and
         "choices" are not handled as expected. For example, if you
         specify a required value in a config file, you still have to
         specify it again on the command line.
      -  doesn't work with python 3 yet
      -  no unit tests, code not well documented

-  appsettings v0.5 (https://pypi.python.org/pypi/appsettings)

   -  Good:

      -  supports config file (yaml format) and env_var parsing
      -  supports config-file-only setting for specifying lists and
         dicts

   -  Bad:

      -  passes in config file and env settings via parse_args
         namespace param
      -  tests not finished and don't work with python3 (import
         StringIO)

-  argparse_config v0.5.1
   (https://pypi.python.org/pypi/argparse_config)

   -  Good:

      -  similar features to ConfArgParse v1.0.15

   -  Bad:

      -  doesn't work with python3 (error during pip install)

-  yconf v0.3.2 - (https://pypi.python.org/pypi/yconf) - features
   and interface not that great
-  hieropt v0.3 - (https://pypi.python.org/pypi/hieropt) - doesn't
   appear to be maintained, couldn't find documentation

-  configurati v0.2.3 - (https://pypi.python.org/pypi/configurati)

   -  Good:

      -  JSON, YAML, or Python configuration files
      -  handles rich data structures such as dictionaries
      -  can group configuration names into sections (like .ini files)

   -  Bad:

      -  doesn't work with python3
      -  2+ years since last release to PyPI
      -  apparently unmaintained


Design choices:

1. all options must be settable via command line. Having options that
   can only be set using config files or env. vars adds complexity to
   the API, and is not a useful enough feature since the developer can
   split up options into sections and call a section "config file keys",
   with command line args that are just "--" plus the config key.
2. config file and env. var settings should be processed by appending
   them to the command line (another benefit of #1). This is an
   easy-to-implement solution and implicitly takes care of checking that
   all "required" args are provied, etc., plus the behavior should be
   easy for users to understand.
3. configargparse shouldn't override argparse's
   convert_arg_line_to_args method so that all argparse unit tests
   can be run on configargparse.
4. in terms of what to allow for config file keys, the "dest" value of
   an option can't serve as a valid config key because many options can
   have the same dest. Instead, since multiple options can't use the
   same long arg (eg. "--long-arg-x"), let the config key be either
   "--long-arg-x" or "long-arg-x". This means the developer can allow
   only a subset of the command-line args to be specified via config
   file (eg. short args like -x would be excluded). Also, that way
   config keys are automatically documented whenever the command line
   args are documented in the help message.
5. don't force users to put config file settings in the right .ini
   [sections]. This doesn't have a clear benefit since all options are
   command-line settable, and so have a globally unique key anyway.
   Enforcing sections just makes things harder for the user and adds
   complexity to the implementation.
6. if necessary, config-file-only args can be added later by
   implementing a separate add method and using the namespace arg as in
   appsettings_v0.5

Relevant sites:

-  http://stackoverflow.com/questions/6133517/parse-config-file-environment-and-command-line-arguments-to-get-a-single-coll
-  http://tricksntweaks.blogspot.com/2013_05_01_archive.html
-  http://www.youtube.com/watch?v=vvCwqHgZJc8#t=35


.. |Travis CI Status for bw2/ConfigArgParse| image:: https://travis-ci.org/bw2/ConfigArgParse.svg?branch=master


