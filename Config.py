from datetime import datetime
from dateutil import parser
import json
import pprint


"""Idea here being to start with something that is decomposed so it's easier to
make do json in *and* out, differences between configs and config extension.
"""


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
        return parser.parse(value)
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
    """Top level config class for common methods."""

    def __init__(self):
        # container for validated properties with JSON names
        self._data = {}

    def __repr__(self):
        s = '< %s %s >' % (self.__class__.__name__,
                           pprint.pformat(self._data))
        return s

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
                #TODO log warning
                print 'Unknown attribute "%s", skipping' % key

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

    def make_tls_policy_dict(self, policy_dict):
        tls_policy_dict = self._data['tls-policies']
        for domain_suffix, settings in policy_dict.iteritems():
            new_domain_policy = TLSPolicy(domain_suffix)
            try:
                new_domain_policy.from_json_dict(settings)
            except ConfigError as e:
                raise
            tls_policy_dict[domain_suffix] = new_domain_policy

    def make_acceptable_mxs_dict(self, mxs_dict):
        acceptable_mxs_dict = self._data['acceptable-mxs']
        for domain, settings in mxs_dict.iteritems():
            new_domain_policy = AcceptableMX(domain)
            try:
                new_domain_policy.from_json_dict(settings)
            except ConfigError as e:
                raise
            acceptable_mxs_dict[domain] = new_domain_policy

    def is_valid(self):
        #TODO implement with checks to make sure domains don't overlap
        # and every acceptable mx has a tls policy, etc.
        raise NotImplemented
        

class TLSPolicy(BaseConfig):

    ENFORCE_MODES = ('enforce', 'log-only')
    TLS_VERSIONS = ('TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3')

    def __init__(self, domain_suffix):
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
                #TODO wat, log this instead
                print 'Unknown key %s' % key

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
        """Should this be dealing only with strings processed by map ... lower()?"""
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
    def __init__(self, domain):
        super(self.__class__, self).__init__()
        self.domain = domain
        self._data['accept-mx-domains'] = []

    def add_acceptable_mx(self, domain_suffix):
        unique_domain_suffixes = set(self._data['accept-mx-domains'])
        unique_domain_suffixes.add(domain_suffix)
        self._data['accept-mx-domains'] = list(unique_domain_suffixes)

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
            else:
                #TODO add logging for this
                print 'warning: unknown key %s' % key


class ConfigError(ValueError):
    def __init__(self, message):
        super(self.__class__, self).__init__(message)

