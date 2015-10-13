from datetime import datetime
import json


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
        raise ValueError('Config value %s is an invalid boolean value.' % attr_name)
    return bool_value


def parse_timestamp(value, attr_name):
    #TODO support full extended timestamp "2014-06-06T14:30:16+00:00" as well
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            ts = int(value)
            dt = datetime.fromtimestamp(ts)
        except:
            raise ValueError('Config value %s is an invalid timestamp integer.' % attr_name)
    return dt


def verify_member_of(value, member_list, attr_name):
    if value not in member_list:
        raise ValueError('Config value "%s" must be one of (%s)' % (
            attr_name, ', '.join(member_list))
        )
    return value


def verify_string(value, attr_name, max_length=200):
    if not isinstance(value, (str, unicode)):
        raise TypeError('Config value %s must be a string.' % attr_name)
    if len(value) > max_length:
        raise ValueError('Config value %s is too long.' % attr_name)
    return value


class Config(object):
    """Config container for StartTLS Everywhere configuration.
    
    Intended as a simple container that unifies where validatation occurs,
    and is capable of comparing configs to warn of things like changing
    certificate fingerprints from one scan to the next.

    There is a one to one mapping of the object attributes to the JSON
    object keys, albeit with dashes replaced with underscores.
    """

    def __init__(self):
        # container for validated properties with JSON names
        self._data = {}

        self.tls_policies = []
        self.acceptable_mxs = []

    def __add__(self, other_config):
        """Allow addition but not really of *full* configs, need to flesh that out."""
        #TODO add this
        raise NotImplemented

    def __repr__(self):
        #TODO fix this generically, and maybe put it in the inheritence tree
        s = '<StartTLS-Everywhere Config\n%s\n>' % (self._data.iteritems())
        return s

    def update(self, other_config):
        """Update properties of config from a 'newer' config and force verification."""
        #TODO add this
        raise NotImplemented

    def load_from_json_file(self, json_filename, f_open=open):
        #TODO add robust catching and checking
        # try:
        with f_open(json_filename, 'r') as f:
            json_str = f.read()
        json_dict = json.loads(json_str)
        # except oserr
        # except json parse err
        self.from_json_dict(json_dict)

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
                self.tls_policies = self.make_tls_policy_dict(val)
            elif key == 'acceptable-mxs':
                self.acceptable_mxs = self.make_acceptable_mxs_dict(val)
            else:
                #TODO log warning
                print 'Unknown attribute "%s", skipping' % key

    def to_json(self):
        #TODO implement output and make sure it can be re-input with identical results
        raise NotImplemented

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
        tls_policy_dict = {}
        for domain_suffix, settings in policy_dict.iteritems():
            new_domain_policy = TLSPolicy(domain_suffix)
            #TODO define config errs and use
            #try
            new_domain_policy.from_json_dict(settings)
            #except config err
            tls_policy_dict[domain_suffix] = new_domain_policy
        return tls_policy_dict

    def make_acceptable_mxs_dict(self, mxs_dict):
        acceptable_mxs_dict = {}
        for domain, settings in mxs_dict.iteritems():
            new_domain_policy = AcceptableMX(domain)
            #TODO define config errs and use
            #try
            new_domain_policy.from_json_dict(settings)
            #except config err
            acceptable_mxs_dict[domain] = new_domain_policy
        return acceptable_mxs_dict

    def is_valid(self):
        #TODO implement with checks to make sure domains don't overlap
        # and every acceptable mx has a tls policy, etc.
        raise NotImplemented


class TLSPolicy(object):

    ENFORCE_MODES = ('enforce', 'log-only')
    TLS_VERSIONS = ('TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3')

    def __init__(self, domain_suffix):
        # container for validated properties with JSON names
        self._data = {}
        self.domain_suffix = domain_suffix

        #TODO add me
        self.accept_spki_hashs = None
        #TODO add me
        self.error_notification = None

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


class AcceptableMX(object):
    """Holds acceptable MX domain suffixes for a single mail serving domain.

    Such as for gmail.com that single mail serving suffix domain is:
        gmail-smtp-in.l.google.com.

    Configuration of the acceptable MX suffix domains must match up with TLS policies
    for the suffix domains.
    """
    def __init__(self, domain):
        self.domain = domain
        # container for validated properties with JSON names
        self._data = {}
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
