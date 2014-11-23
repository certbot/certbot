## Documentation

### Class Overview
#### Client
client.py contains the main logic in the client.  
Running sudo ./letsencrypt.py will essentially start the program in the Client.authenticate() method.  The client code isn't terribly complex and should be fairly easy to read and understand.  Note that this class also contains the revocation functionality.

#### Configurator
Recently refactored to allow for modular classes representing different webservers.
Configurator (configurator.py) - abstract base class that contains the API outside classes can use to interact with the Configurator objects. As an abstract base class, all child configurators must implement all of the abstract base methods.

AugeasConfigurator(Configurator) (augeas_configurator.py) - Intended to be further subclassed, this class contains all of the methods and variables for saving and reverting configuration changes that are made with the open source project [Augeas](http://augeas.net/).  Essentially, configurator's that use Augeas can reuse all of this "save" infrastructure that is designed to be "ACID" compliant.  If the save transaction isn't executed completely, the save state will be reverted the next time the program starts, which is essential for avoiding misconfigurations.  More on the current "save" infrastructure below.

ApacheConfigurator(AugeasConfigurator) (apache_configurator.py) - Represents an Apache webserver.  This configurator uses Augeas and its Httpd lens.

NginxConfigurator(AugeasConfigurator) (nginx_configurator.py) - Currently just a stub class.  There is an nginx lens in the Augeas project, so it should be possible to parse and edit configuration files with it.  (I have not worked with the nginx lens yet, so I do not know the difficulty in getting it production ready)

#### Validator
In order to guarantee correctness at the end of the configuration edits, I would like to implement a class that can validate standard changes.  Is HTTPS enabled for example.com?  Does it use OCSP stapling? ect...  This should provide confidence in the end result, which allows configuration changes to be reverted if the configuration isn't sufficient.  It will also be quite helpful in testing.  This is currently just a stub class.

#### Display
Tries to separate out all output logic through the use of a "display" object.  This allows classes like the Client to simply say display.generic_menu(...) and the output will be formatted correctly depending on whether the user wanted the "text mode", "dialog mode"... or other modes in the future.

#### Logging
Simple singleton logging utility. Once instantiated (either curses, or stdout currently), you will receive all output on your chosen interface that is at or above the level of notification.  The levels include: TRACE, DEBUG, INFO, WARN, ERROR, and FATAL.  Logging takes the form of logger.error(string), logger.warn(...), logger.info(...)

#### Utility Functions
There are two files that contain utility functions, le_util.py and crypto_util.py.
le_util.py (le = lets encrypt) functions are generic and meant to be useful throughout the project.
crypto_util.py contains cryptographic functions.

#### Schematas
acme.py and the schematas are meant to validate the protocol messages.  They confirm that all fields in all messages are appropriate which should aid in testing, debugging and the security of the project.  Messages are verified in both the outbound and inbound directions.


### Configuration and Saving with Augeas

#### Augeas Configuration - all configuration changes are handled by Augeas which uses
a subset of XPath to find changes.  Since the Augeas Apache lens does not
recursively search through Apache config files and directories that have
been added using the "include" apache directive, I had to manually do this
inclusion by myself.

#### Saving/Restoring Files
augeas_configurator.py has been designed such that the
program can fail or shutdown at anytime and be restarted back into a useful
and clean configuration state.
In general, there are two types of saves, TEMPORARY and PERMANENT.
*TEMPORARY saves are used for challenges.  These are configuration changes
that should not be checkpointed. The user cannot rollback to one of these
states.
*PERMANENT saves are basically any changes that are not for performing challenges.

Mutual Exclusion: If there is a TEMPORARY save ongoing, you may not make any
permanent saves. Likewise, if you are in the process of creating a PERMANENT
CHECKPOINT, you can not create a TEMPORARY save.

Before any save (any configuration change), all associated changed files are
added to temporary directories. These temporary directories contain a list of
all newly created files, all of the files before they were changed, and
human-readable notes describing the changes.

Once a PERMANENT save is ready to be turned into a checkpoint, it is given
a "title" and all files from the IN_PROGRESS save directory are moved to a
permanent time-stamped directory.

Save directories contain all of the information necessary to rollback changes,
and are created before any actual change to the configuration takes place.

Upon AugeasConfigurators startup, the system should check to see if there were any
IN_PROGRESS or TEMPORARY saves and will immediately roll them back,
placing the client in a stable, checkpointed state.

Some finesse is required to use this system appropriately.
Here are the main points.

1. Before creating files you must specify their paths to the Configurator.

2. self.save_notes are expected to be included for changes. These are
human-readable notes which can be read with --view-checkpoints

3. Removing user files is dangerous and is not currently supported.
If this feature is desired in the future, the save infrastructure will have to
be updated to support it in a similar manner to adding files.

There are plenty of examples throughout the code.
Normal Augeas configuration changes do not modify files until all of the
changes are saved.
The main function is Configurator.save(title=None, temporary=False)

## Notes on Security

Threat Model: Attackers can have user level access to the filesystem (perhaps from an unpatched vulnerability in the existing webserver).  The attacker should not be able to receive a trusted certificate or exploit the Let's Encrypt client via a privilege escalation attack.

The security and safety of this code is extremely important.  The program runs with root privileges and its goal is to display authoritative ownership of the service.  As with securing any program, all inputs must be carefully scrutinized.  The Let's Encrypt client attempts to guarantee all inputs are "trusted". Most of the inputs to Let's Encrypt are sensitive and many are [executed](http://olsner.se/2008/01/21/an-excursion-in-mod_rewrite/) in one way or another.  Therefore all inputs must be checked for root privilege in order to avoid [privilege escalation attacks](https://en.wikipedia.org/wiki/Privilege_escalation).  

le_util.py contains several helper functions to ensure a safe execution environment.  These functions are also designed to avoid [TOCTOU attacks](http://www.hpenterprisesecurity.com/vulncat/en/vulncat/cpp/file_access_race_condition.html).

The project's goal is to minimally raise the attack surface of Let's Encrypt webservers.  The code aims avoid the  introduction of any new vulnerabilities to an existing webserver.  If you find any vulnerabilities given this threat model, please raise a Github issue about it.