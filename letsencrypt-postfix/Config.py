#!/usr/bin/env python
from datetime import datetime
from dateutil import parser as dateutil_parser
import collections
import json
import logging
import pprint


"""Idea here being to start with something that is decomposed so it's easier to
make do json in *and* out, differences between configs and config extension.
"""

#TODO scope logging and handlers better, control verbosity by command line flags
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


def parse_bool_from_json(value, attr_name):
    if value in ('true', '1', 1, 'yes'):
        bool_value = True
    elif value in ('false', '0', 0, 'no'):
        bool_value = False
    elif value in (True, False):
        bool_value = value
    else:
        raise ConfigError('Config value %s is an invalid boolean value.' % attr_name)
    return bool_value


def parse_timestamp(value, attr_name):
    if isinstance(value, datetime):
        return value
    try:
        ts = int(value)
        return datetime.fromtimestamp(ts)
    except (TypeError, ValueError):
        pass
    try:
        return dateutil_parser.parse(value)
    except (TypeError, ValueError):
        raise ConfigError('Config value %s is an invalid date or timestamp.' % attr_name)


def verify_member_of(value, member_list, attr_name):
    if value not in member_list:
        raise ConfigError('Config value "%s" must be one of (%s)' % (
            attr_name, ', '.join(member_list))
        )
    return value


def verify_string(value, attr_name, max_length=200):
    if not isinstance(value, (str, unicode)):
        raise ConfigError('Config value %s must be a string.' % attr_name)
    if len(value) > max_length:
        raise ConfigError('Config value %s is too long.' % attr_name)
    return value


def to_dict(config_dict):
    """Cleans up BaseConfig children to be serialized."""
    d = {}
    for key, val in config_dict.iteritems():
        if isinstance(val, BaseConfig):
            d[key] = to_dict(val._data)
        elif isinstance(val, datetime):
            d[key] = val.strftime('%Y-%m-%dT%H:%M:%S%z')
        elif isinstance(val, dict):
            d[key] = to_dict(val)
        else:
            d[key] = val
    return d


class BaseConfig(object):
    """Top level config class for common methods.
    
    Requirements for using class:
    - list all properties with getters *and* setters in class
    variable 'config_properties'
    - __init__ of child classes must be callable with *only*
    keyword arguments to allow method calls to update to create
    a new config
    ... more ...
    """

    config_properties = []

    def __init__(self):
        # container for validated properties with JSON names
        self._data = {}

    def __repr__(self):
        s = '< %s %s >' % (self.__class__.__name__,
                           pprint.pformat(self._data))
        return s

    def update(self, newer_config, merge=False, **kwargs):
        """Create a fresh config combining the new and old configs.

        It does this by iterating over the 'config_properties' class
        attribute which contains names of property attributes for the config.

        Two methods of combining configs are possible, an 'update' and
        a 'merge', the latter set by the keyword argument 'merge=True'.
        
        An update overrides older values with new values -- even if those
        new values are None.  Update will remove values that are present in
        the old config if they are not present in the new config.

        A merge by comparison will allow old values to persist if they are
        not specified in the new config.  This can be used for end-user
        customizations to override specific settings without having to re-create
        large portions of a config to override it.

        Arguments:
          newer_config: A config object to combine with the current config.
          merge: Allows old values not overridden to survive into the fresh config.

        Returns:
          A config object of the same sort as called upon.
        """
        # removed 'merge' kw arg - and it was passed to constructor
        # make a note to not do that, consume it on the param list
        fresh_config = self.__class__(**kwargs)
        logger.debug('from parent update kwargs %s' % kwargs)
        logger.debug('from parent update merge %s' % merge)
        if not isinstance(newer_config, self.__class__):
            raise ConfigError('Attempting to update a %s with a %s' % (
                self.__class__,
                newer_config.__class__))
        for prop_name in self.config_properties:
            # get the specified property off of the current class
            prop = self.__class__.__dict__.get(prop_name)
            assert prop
            new_value = prop.fget(newer_config)
            old_value = prop.fget(self)
            if new_value is not None:
                prop.fset(fresh_config, new_value)
            elif merge and old_value is not None:
                prop.fset(fresh_config, old_value)
        return fresh_config

    def merge(self, newer_config, **kwargs):
        """Combines configs and keeps old values if they are not overridden.

        See docstring for 'update' method for more details.

        Arguments:
          newer_config: A config object to combine with the current config.
          merge: Allows old values not overridden to survive into the fresh config.

        Returns:
          A config object of the same sort as called upon.
        """
        kwargs['merge'] = True
        logger.debug('from parent merge: %s' % kwargs)
        return self.update(newer_config, **kwargs)

    def to_json(self):
        d = to_dict(self._data)
        return json.dumps(d)

    def write_to_json_file(self, json_filename, f_open=open):
        data = self.to_json()
        try:
            with f_open(json_filename, 'w') as f:
                f.write(data)
        except IOError:
            raise

    def load_from_json_file(self, json_filename, f_open=open):
        try:
            with f_open(json_filename, 'r') as f:
                json_str = f.read()
            json_dict = json.loads(json_str)
        except IOError:
            raise
        except ValueError:
            raise ConfigError('No valid JSON found in file: %s' % json_filename)
        self.from_json_dict(json_dict)

    def from_json_dict(self, json_dict):
        raise NotImplmented('BaseConfig should not be populated.')


class Config(BaseConfig):
    """Config container for StartTLS Everywhere configuration.
    
    Intended as a simple container that unifies where validatation occurs,
    and is capable of comparing configs to warn of things like changing
    certificate fingerprints from one scan to the next.

    There is a one to one mapping of the object attributes to the JSON
    object keys, albeit with dashes replaced with underscores.
    """

    def __init__(self):
        super(self.__class__, self).__init__()
        self._data['tls-policies'] = {}
        self._data['acceptable-mxs'] = {}

    def __add__(self, other_config):
        """Allow addition but not really of *full* configs, need to flesh that out."""
        #TODO add this
        raise NotImplemented

    def update(self, other_config):
        """Update properties of config from a 'newer' config and force verification."""
        #TODO add this
        new_config = Config()
        raise NotImplemented

    def from_json_dict(self, json_dict):
        """Assign JSON data to Config properties and declare sub-objects.

        Let's property verification methods do the heavy lifting and mostly
        maps between the JSON config names and attributes.  Keeps track of
        unused variables and warns about them.
        """
        for key, val in json_dict.iteritems():
            if key == 'author':
                self.author = val 
            elif key == 'comment':
                self.comment = val
            elif key == 'expires':
                self.expires = val
            elif key == 'timestamp':
                self.timestamp = val
            elif key == 'tls-policies':
                self.make_tls_policy_dict(val)
            elif key == 'acceptable-mxs':
                self.make_acceptable_mxs_dict(val)
            else:
                logger.warn('Unknown attribute "%s", skipping' % key)

    @property
    def author(self):
        return self._data.get('author')

    @author.setter
    def author(self, value):
      self._data['author'] = verify_string(value, 'author')

    @property
    def comment(self):
        return self._data.get('comment')

    @comment.setter
    def comment(self, value):
      self._data['comment'] = verify_string(value, 'comment')

    @property
    def expires(self):
        return self._data.get('expires')

    @expires.setter
    def expires(self, value):
        self._data['expires'] = parse_timestamp(value, 'expires')

    @property
    def timestamp(self):
        return self._data.get('timestamp')

    @timestamp.setter
    def timestamp(self, value):
        self._data['timestamp'] = parse_timestamp(value, 'timestamp')

    @property
    def tls_policies(self):
        return self._data.get('tls-policies')

    @property
    def acceptable_mxs(self):
        return self._data.get('acceptable-mxs')

    def make_tls_policy_dict(self, policy_dict):
        tls_policy_dict = self.tls_policies
        for domain_suffix, settings in policy_dict.iteritems():
            new_domain_policy = TLSPolicy(domain_suffix)
            try:
                new_domain_policy.from_json_dict(settings)
            except ConfigError as e:
                raise
            tls_policy_dict[domain_suffix] = new_domain_policy

    def get_tls_policy(self, mx_domain):
        return self.tls_policies.get(mx_domain)

    def make_acceptable_mxs_dict(self, mxs_dict):
        acceptable_mxs_dict = self._data['acceptable-mxs']
        for domain, settings in mxs_dict.iteritems():
            new_domain_policy = AcceptableMX(domain)
            try:
                new_domain_policy.from_json_dict(settings)
            except ConfigError as e:
                raise
            acceptable_mxs_dict[domain] = new_domain_policy

    def get_address_domains(self, mx_hostname, mx_to_domain_map):
        """Do a fuzzy DNS host match on provided map to get lists of policies.

        Args:
          mx_hostname (string): The hostname from an MX record.
          mx_to_domain_map: Mapping from MX hosts to AcceptableMX
              policies, the same AcceptableMX policy may occur more
              than once. e.g. {'mx_host3': set(AcceptableMX, ...)}
              The map can be generated by Config.get_mx_to_domain_policy_map.

        Returns:
          The set containing all AcceptableMX policies that list the
          provided MX host as viable.
        """
        labels = mx_hostname.split(".")
        for n in range(1, len(labels)):
            parent = "." + ".".join(labels[n:])
            if parent in mx_to_domain_map:
                return mx_to_domain_map[parent]
        return None

    def get_mx_to_domain_policy_map(self):
        """Create mapping of MX hostnames to sets of AcceptableMX policies.

        Generate a dictionary that is typically used in log analysis
        (e.g. if your MTA logs interact with beta.innotech.com you use
        this mapping to tell you it used the innotech.com AcceptableMX
        policy or policies). There are of course complications.
        """
        # create reverse mapping dictionary as well for auditing
        # and reviewing logs
        mx_to_domain_policy = collections.defaultdict(set)

        for mx_host, domain_policy in self.get_all_mx_items():
            existing_mx_policies = mx_to_domain_policy.get(mx_host)
            if existing_mx_policies:
                existing_domains = [ e.domain for e in existing_mx_policies ]
                if domain_policy.domain not in existing_domains:
                    #TODO plenty of room to enforce a security policy here
                    # this is also the case of google apps personal domains
                    msg = ('Attempting to add domain policy (%s) for MX host but MX'
                           ' host already has a domain policy (%s), appending...')
                    logger.debug(msg % (domain_policy.domain,
                                        ', '.join(existing_domains)))
            mx_to_domain_policy[mx_host].add(domain_policy)
        return mx_to_domain_policy

    def get_all_mx_items(self):
        """Iterate over (mx_host, mx_policy) - be sure to dedup!"""
        all_mx_items = []
        for policy in self.acceptable_mxs.values():
          accepted_mxs = policy.accept_mx_domains
          all_mx_items.extend([(mx_host, policy)
                               for mx_host in accepted_mxs])
        return all_mx_items

    def get_all_mx_hosts(self):
        all_mx_hosts = []
        [ all_mx_hosts.extend(domain_policy.acceptable_mxs)
          for domain_policy in self.acceptable_mxs.values() ]
        return all_mx_hosts

    def is_valid(self):
        #TODO implement checks to make sure domains don't overlap
        #TODO add debug logging for troubleshooting sake
        for mx_config in self.acceptable_mxs.values():
            if not mx_config.is_valid():
                return False
            for domain_suffix in mx_config.accept_mx_domains:
                # check to make sure every accepted MX has a TLS policy
                if not domain_suffix in self.tls_policies:
                    return False
        all_mx_hosts = self.get_all_mx_hosts()
        for domain_suffix, tls_config in self.tls_policies.iteritems():
            if not tls_config.is_valid():
                return False
            # make sure no unclaimed TLS policies have made their way in
            if domain_suffix not in all_mx_hosts:
                return False
        return True
        

class TLSPolicy(BaseConfig):

    ENFORCE_MODES = ('enforce', 'log-only')
    TLS_VERSIONS = ('TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3')

    config_properties = ['comment', 'enforce_mode', 'min_tls_version',
                         'require_tls', 'require_valid_certificate']
 
    def __init__(self, domain_suffix=None):
        super(self.__class__, self).__init__()
        self.domain_suffix = domain_suffix
        #TODO add support for two designed but yet unsupported attrs
        # self._data['accept-spki-hashs'] = None
        # self._data['error-notification'] = None

    def from_json_dict(self, json_dict):
        for key, val in json_dict.iteritems():
            if key == 'comment':
                self.comment = val
            elif key == 'enforce-mode':
                self.enforce_mode = val
            elif key == 'min-tls-version':
                self.min_tls_version = val
            elif key == 'require-tls':
                self.require_tls = val
            elif key == 'require-valid-certificate':
                self.require_valid_certificate = val
            else:
                logger.warn('Unknown key %s' % key)

    def is_valid(self):
        """Do simple check that config contains all required values.

        Should find a way to expose easily which config values
        are required, at least place in error messages such that
        incomplete configs will expose it.
        """
        required_attrs = ('enforce-mode', 'min-tls-version',
                          'require-tls')
        values_set = [self._data.get(attr) for attr in required_attrs]
        if not all(values_set):
            return False
        else:
            return True

    def update(self, newer_policy, **kwargs):
        if not kwargs.get('domain_suffix'):
            kwargs['domain_suffix'] = self.domain_suffix
        fresh_policy = super(self.__class__, self).update(newer_policy,
                                                          **kwargs)
        logger.debug('from TLS child update %s' % kwargs)
        return fresh_policy

    def merge(self, newer_policy, **kwargs):
        logger.debug('from TLS child merge: %s' % kwargs)
        fresh_policy = super(self.__class__, self).merge(newer_policy,
                                                         domain_suffix=self.domain_suffix)
        return fresh_policy

    @property
    def comment(self):
        return self._data.get('comment')

    @comment.setter
    def comment(self, value):
        self._data['comment'] = verify_string(value, 'comment')

    @property
    def enforce_mode(self):
        return self._data.get('enforce-mode')

    @enforce_mode.setter
    def enforce_mode(self, value):
        self._data['enforce-mode'] = verify_member_of(value, self.ENFORCE_MODES, 'enforce-mode')

    @property
    def min_tls_version(self):
        return self._data.get('min-tls-version')

    @min_tls_version.setter
    def min_tls_version(self, value):
        """TODO: Should this be dealing only with strings processed by map ... lower()?"""
        tls_versions = [ver.lower() for ver in self.TLS_VERSIONS]
        tls_versions.extend(self.TLS_VERSIONS)
        self._data['min-tls-version'] = verify_member_of(value, tls_versions, 'min-tls-version')
        
    @property
    def require_tls(self):
        return self._data.get('require-tls')

    @require_tls.setter
    def require_tls(self, value):
        self._data['require-tls'] = parse_bool_from_json(value, 'require-tls')

    @property
    def require_valid_certificate(self):
        return self._data.get('require-valid-certificate')

    @require_valid_certificate.setter
    def require_valid_certificate(self, value):
        self._data['require-valid-certificate'] = parse_bool_from_json(value, 'require-valid-certificate')


class AcceptableMX(BaseConfig):
    """Holds acceptable MX domain suffixes for a single mail serving domain.

    Such as for gmail.com that single mail serving suffix domain is:
        gmail-smtp-in.l.google.com.

    Configuration of the acceptable MX suffix domains must match up with TLS policies
    for the suffix domains.
    """
    def __init__(self, domain=None):
        super(self.__class__, self).__init__()
        self.domain = domain
        self._data['accept-mx-domains'] = []

    @property
    def accept_mx_domains(self):
        return self._data.get('accept-mx-domains')

    def add_acceptable_mx(self, domain_suffix):
        unique_domain_suffixes = set(self._data['accept-mx-domains'])
        unique_domain_suffixes.add(domain_suffix)
        self._data['accept-mx-domains'] = list(unique_domain_suffixes)

    @property
    def comment(self):
        return self._data.get('comment')

    @comment.setter
    def comment(self, value):
        self._data['comment'] = verify_string(value, 'comment')

    def is_valid(self):
        """Check to make sure there is one acceptable domain suffix.

        This will need to be updated once we can actually test and support
        for more than one acceptable domain suffix.

        TODO: could make this object double check the data it is given with
        DNS queries.
        """
        if len(self._data['accept-mx-domains']) != 1:
            return False
        else:
            return True

    def from_json_dict(self, json_dict):
        for key, val in json_dict.iteritems():
            if key == 'accept-mx-domains':
                if isinstance(val, list):
                    for domain_suffix in val:
                        self.add_acceptable_mx(domain_suffix)
                else:
                    self.add_acceptable_mx(val)
            elif key == 'comment':
                self.comment = val
            else:
                logger.warn('warning: unknown key %s' % key)

    def update(self, newer_policy, **kwargs):
        logger.debug('from MX child update got %s' % kwargs)
        if not kwargs.get('domain'):
            kwargs['domain'] = self.domain
        fresh_policy = super(self.__class__, self).update(newer_policy,
                                                          **kwargs)
        if kwargs.get('merge'):
            new_accepted_mxs = set(self.accept_mx_domains)
            new_accepted_mxs = new_accepted_mxs.union(newer_policy.accept_mx_domains)
        else:
            new_accepted_mxs = newer_policy.accept_mx_domains
        for domain in new_accepted_mxs:
            fresh_policy.add_acceptable_mx(domain)
            
        return fresh_policy

    def merge(self, newer_policy, **kwargs):
        logger.debug('from MX child merge: %s' % kwargs)
        fresh_policy = super(self.__class__, self).merge(newer_policy,
                                                         **kwargs)
        return fresh_policy


class ConfigError(ValueError):
    def __init__(self, message):
        super(self.__class__, self).__init__(message)
