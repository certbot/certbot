"""DNS Authenticator for Plesk."""
import logging
import types
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Plesk

    This Authenticator uses the Plesk API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Plesk for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Plesk credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Plesk API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Plesk credentials INI file',
            {
                'token': 'API token for Plesk account',
                'username': 'Username for Plesk account',
                'password': 'Password for Plesk account',
                'hostname': 'Hostname for Plesk server',
                'port'    : 'port for Plesk server'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_plesk_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_plesk_client().del_txt_record(domain, validation_name, validation)

    def _get_plesk_client(self):
        return _PleskClient(self.credential.conf('hostname'),
                        self.credentials.conf('port'),
                        self.credentials.conf('protocol'),
                        self.credentials.conf('username'),
                        self.credentials.conf('password'),
                        self.credentials.conf('token'))


class _PleskClient(object):
    """
    Encapsulates all communication with the Plesk API.
    """

    def __init__(self, hostname, port=8443, protocol='https', username='', password='', token=''):
        self.manager = _Plesk(self, hostname, port, username, password, token);

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Plesk
                                            API
        """

        try:
            domain = self._find_domain(domain_name)
        except plesk.Error as e:
            hint = None

            if str(e).startswith("Unable to authenticate"):
                hint = 'Did you provide a valid API token? Or username/password?'

            logger.debug('Error finding domain using the Plesk API: %s', e)
            raise errors.PluginError('Error finding domain using the Plesk API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

        try:
            result = self.manager.create_new_domain_record(domain,
                type='TXT',
                name=record_name,
                data=record_content)

            record_id = result['domain_record']['id']

            logger.debug('Successfully added TXT record with id: %d', record_id)
        except plesk.Error as e:
            logger.debug('Error adding TXT record using the Plesk API: %s', e)
            raise errors.PluginError('Error adding TXT record using the Plesk API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domain = self._find_domain(domain_name)
        except plesk.Error as e:
            logger.debug('Error finding domain using the Plesk API: %s', e)
            return

        try:
            domain_records = self.manager.get_all_domain_data(domain)

            matching_records = [record for record in domain_records
                                if record.type == 'TXT'
                                and record.name == self._compute_record_name(domain, record_name)
                                and record.data == record_content]
        except plesk.Error as e:
            logger.debug('Error getting DNS records using the Plesk API: %s', e)
            return

        for record in matching_records:
            try:
                logger.debug('Removing TXT record with id: %s', record.id)
                self.manager.del_domain(record.id)
            except plesk.Error as e:
                logger.warn('Error deleting TXT record %s using the Plesk API: %s',
                            record.id, e)

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `~plesk.Domain`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self.manager.get_all_domains()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain.name == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from Plesk's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain.name)[0]

class _Plesk:
    domainnames = ''
    def __init__(self, host, port = 8443, protocol = 'https', username='', password='', token=''):
        self.PleskApi = PleskApiClient(host, port, protocol)
        if token:
            self.PleskApi.set_secret_key(token)
        else:
            self.PleskApi.set_credentials(username, password)

    def add_domain(self,domain,type,host,value):
        """
        Add a new record to the domain with some type and value
        First we need the site id, after that  we can add the record to that site.

        :param str domain 
        :param str type 
        :param str host
        :param str value
        :returns list (status, values)
        """
        siteres = get_siteid(domain)
        if siteres[0] != "ok":
            return siteres
        siteid = siteres[0]
        add_request = "<packet><dns><add_rec><site-id>{0}</site-id><type>{1}</type><host>{2}</host><value>{3}</value></add_rec></dns></packet>".format(siteid,type,host,value)
        add_response = self.PleskApi.request(add_request)
        dom = xml.dom.minidom.parseString(add_response)
        rec=dom.getElementsByTagName("packet")[0].getElementsByTagName("dns")[0].getElementsByTagName("add_rec")[0].getElementsByTagName("result")[0]
        syserr=dom.getElementsByTagName("packet")[0].getElementsByTagName("system")
        if syserr:
            return (getText(syserr[0].getElementsByTagName("status")[0].childNodes), getText(syserr[0].getElementsByTagName("errcode")[0].childNodes), getText(syserr[0].childNodes))
        if getText(rec.getElementsByTagName("status")[0].childNodes) == "ok":
            result = ("ok",getText(rec.getElementsByTagName("id")[0].childNodes))
        else:
            result = ("error", getText(rec.getElementsByTagName("errcode")[0].childNodes), getText(rec.getElementsByTagName("errtext")[0].childNodes))
        return result

    def del_domain(self,del_id):
        """
        Deletes the domain element name by id
        The return is either (error,code,text)
                             or the (ok,id).
        :param str del_id
        """
        del_request = "<packet><dns><del_rec><filter><id>{0}</id></filter></del_rec></dns></packet>".format(del_id)
        del_response = self.PleskApi.request(del_request)
        dom = xml.dom.minidom.parseString(del_response)
        syserr=dom.getElementsByTagName("packet")[0].getElementsByTagName("system")
        if syserr:
            return (getText(syserr[0].getElementsByTagName("status")[0].childNodes), getText(syserr[0].getElementsByTagName("errcode")[0].childNodes), getText(syserr[0].childNodes))
        rec=dom.getElementsByTagName("packet")[0].getElementsByTagName("dns")[0].getElementsByTagName("del_rec")[0].getElementsByTagName("result")[0]
        if getText(rec.getElementsByTagName("status")[0].childNodes) == "ok":
            result = ("ok", getText(rec.getElementsByTagName("id")[0].childNodes))
        else:
            result = ("error", getText(rec.getElementsByTagName("errcode")[0].childNodes), getText(rec.getElementsByTagName("errtext")[0].childNodes))
        return result

    def create_new_domain_record(self, domain, type, name, data):
        """
        create_new_domain_record....
        :param str domain
        :param str type
        :param str name
        :param str data
        """
        res=self.add_domain(domain,type,name,data)
        if res[0] == "error" and res[1] == "1007":
            res = self.destroy_domain_record(domain, type, name)
            if res[0] == "ok":
                res = self.add_domain(domain,type,name,data)
        if res[0] == "error":
            logger.error("Create error: {0} ( {1} )".format(res[1],res[2]))
        return res[0]

    def destroy_domain_record(self, domain, type, name):
        """
        deletes a domain by searching for the id and then removing the name.
        First lookup the ID, geting all domain data: (returns  (ok, [list of domain values]) or (error, errno, errtest).
        the kicking all matching names & types

        :param str type
        :param str name
        :param str data
        """
        list = self.get_all_domain_data(domain) 
        if list[0] != ok:
            return none                     # return failure
        item = "{0}.{1}.".format(name,domain)
        for l in list[1]:
            if (l.name == item) and (l.type == type):
                result = self.del_domain(l.id)
                if result[0] != "ok":
                    logger.error("Error: {0}: {1}\n".format( result[1],result[2]))
                    return "error"
        return "ok"

    def get_siteid(self,domain):
        """
        Get internal plesk id for a site

        :param str domain
        """
        result = self.get_all_domain_data(domain)
        if result[0] == "ok":
            return ("ok", result[1][0].siteid)
        return result

    def get_all_domain_data(self,domain):
        """
        Get all entries for a domain

        :param str domain
        :returns: list of records of domain data
        """
        result=[]
        get_request = "<packet><dns><get_rec><filter><dns-zone-name>{0}</dns-zone-name></filter></get_rec></dns></packet>".format(domain)
        get_response = self.PleskApi.request(get_request)
        dom = xml.dom.minidom.parseString(get_response)
        syserr=dom.getElementsByTagName("packet")[0].getElementsByTagName("system")
        if syserr:
            return (getText(syserr[0].getElementsByTagName("status")[0].childNodes), getText(syserr[0].getElementsByTagName("errcode")[0].childNodes), getText(syserr[0].getElementsByTagName("errtext")[0].childNodes))
        rec=dom.getElementsByTagName("packet")[0].getElementsByTagName("dns")[0].getElementsByTagName("get_rec")[0].getElementsByTagName("result")
        for r in rec:
            if getText(r.getElementsByTagName("status")[0].childNodes) == "ok":
                domain_rec = types.SimpleNamespace()
                domain_rec.id = getText(r.getElementsByTagName("id")[0].childNodes)
                d = r.getElementsByTagName("data")[0]
                domain_rec.siteid = getText(d.getElementsByTagName("site-id")[0].childNodes)
                domain_rec.type = getText(d.getElementsByTagName("type")[0].childNodes)
                domain_rec.name = getText(d.getElementsByTagName("host")[0].childNodes)
                domain_rec.data = getText(d.getElementsByTagName("value")[0].childNodes)
                result.append ( domain_rec )
        return result


    def get_all_domains(self):
        """
        Get all entries for a domain

        :returns: list of available domains
        """
        result=[]
        tresult={}
        get_request = "<packet><dns><get_rec></get_rec></dns></packet>"
        get_response = self.PleskApi.request(get_request)
        dom = xml.dom.minidom.parseString(get_response)
        syserr=dom.getElementsByTagName("packet")[0].getElementsByTagName("system")
        if syserr:
            return (getText(syserr[0].getElementsByTagName("status")[0].childNodes), getText(syserr[0].getElementsByTagName("errcode")[0].childNodes), getText(syserr[0].getElementsByTagName("errtext")[0].childNodes))
        rec=dom.getElementsByTagName("packet")[0].getElementsByTagName("dns")[0].getElementsByTagName("get_rec")[0].getElementsByTagName("result")
        for r in rec:
            if getText(r.getElementsByTagName("status")[0].childNodes) == "ok":
                idx = getText(r.getElementsByTagName("id")[0].childNodes)
                d = r.getElementsByTagName("data")[0]
                siteid = getText(d.getElementsByTagName("site-id")[0].childNodes)
                host = getText(d.getElementsByTagName("host")[0].childNodes)
                if type != 'TXT':                       # too much variance....(DKIM, DMARC, SPF)...
                    if type == "NS" or type == "SOA" or type=="MX":
                        domain = host                   # allready the right format
                    else:
                        names = host.split('.')
                        domain = ".".join(names[1:])    # drop the hostname
                    tresult[siteid]=domain
        for r in tresult:
            result.append(tresult[r])
        return result



# Plesk Python-3 example code.
# Copyright 1999-2016. Parallels IP Holdings GmbH. All Rights Reserved.

import http.client
import ssl

class PleskApiClient:

    def __init__(self, host, port = 8443, protocol = 'https', ssl_unverified = False):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.secret_key = None
        self.ssl_unverified = ssl_unverified

    def set_credentials(self, login, password):
        """
        set_credentials, initialise class with values...

        :param str login
        :param str password
        """
        self.login = login
        self.password = password

    def set_secret_key(self, secret_key):
        """
        set_secret_key can also be used to gain access to plesk server

        :param str secret_key
        """
        self.secret_key = secret_key

    def request(self, request):
        """
        request  - execute a request

        :param str request XML
        :returns str response XML
        """
        headers = {}
        headers["Content-type"] = "text/xml"
        headers["HTTP_PRETTY_PRINT"] = "TRUE"

        if self.secret_key:
            headers["KEY"] = self.secret_key
        else:
            headers["HTTP_AUTH_LOGIN"] = self.login
            headers["HTTP_AUTH_PASSWD"] = self.password

        if 'https' == self.protocol:
            if self.ssl_unverified:
                conn = http.client.HTTPSConnection(self.host, self.port, context=ssl._create_unverified_context())
            else:
                conn = http.client.HTTPSConnection(self.host, self.port)
        else:
            conn = http.client.HTTPConnection(self.host, self.port)

        conn.request("POST", "/enterprise/control/agent.php", request, headers)
        response = conn.getresponse()
        data = response.read()
        return data.decode("utf-8")
