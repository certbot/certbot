"""API Wrap for Dnspod."""
import logging
import requests

logger = logging.getLogger(__name__)

URL_PRE = "https://dnsapi.cn/"

def check_sub_domain(domain, sub_domain):
    # www.example.com => www
    # example.com => @
    # .example.com => @
    # *.example.com => *
    if sub_domain is not None:
        sub_domain = sub_domain.replace("." + domain, "").replace(domain, "")
    if sub_domain is None or sub_domain == "":
        sub_domain = "@"
    return sub_domain

class DnspodClientError(Exception):
    pass

class DnspodClient(object):
    """
    Encapsulates all communication with the Dnspod API.
    """

    def __init__(self, id, token):
        self.token = id + "," + token
        self._domain_list = None

    def _request(self, url, data):
        url = URL_PRE + url
        base_data = {}
        base_data["login_token"] = self.token
        base_data["format"] = "json"
        base_data["lang"] = "en"
        base_data["error_on_empty"] = "no"
        data.update(base_data)
        headers = {
            "User-Agent": "certbot-dns-dnspod/1.0.0 (liaohuqiu@gmail.com)"
        }
        ret = requests.post(url, data, headers=headers)
        json = self._fetch_json(url, data, ret)
        return json

    def _fetch_json(self, url, request_data, r):
        respone_data = {}
        if r is None:
            return respone_data
        if r.status_code != 200:
            logger.error("http request fail, url: %s status_code: %s" % (url, r.status_code))
            raise DnspodClientError("http request fail, url: %s status_code: %s" % (url, r.status_code))
        try:
            respone_data = r.json()
        except ValueError:
            logger.error("response is not json format, url: %s, respone text %s" % (url, r.text))
            raise DnspodClientError("response is not json format, url: %s, respone text %s" % (url, r.text))
        code = int(respone_data.get("status", {}).get("code", 0))
        if code != 1:
            raise DnspodClientError("Unexpected status code: %s, url: %s, request_data: %s, message: %s" % (code, url, request_data, r.text))
        return respone_data

    def get_record_list(self, domain, record_type):
        url = "Record.List"
        data = {}
        data["domain"] = domain
        if record_type:
            data["record_type"] = record_type

        ret = self._request(url, data)
        return ret["records"]

    def add_record(self, domain, sub_domain, record_type, value):
        sub_domain = check_sub_domain(domain, sub_domain)

        url = "Record.Create"
        data = {}
        data["domain"] = domain
        data["sub_domain"] = sub_domain
        data["record_type"] = record_type
        data["value"] = value
        data["record_line_id"] = 0

        ret = self._request(url, data)
        return ret

    def modify_record(self, domain, record_id, record_type, value):
        url = "Record.Modify"
        data = {}
        data["domain"] = domain
        data["record_id"] = record_id
        data["record_type"] = record_type
        data["value"] = value
        data["record_line_id"] = 0

        ret = self._request(url, data)
        return True

    def remove_record(self, domain, record_id):
        url = "Record.Remove"
        data = {}
        data["domain"] = domain
        data["record_id"] = record_id

        ret = self._request(url, data)
        return ret

    def domain_list(self):
        if not self._domain_list:
            url = "Domain.List"
            data = {}
            data["length"] = 3000
            ret = self._request(url, data)
            self._domain_list = {item["name"]: item for item in ret["domains"]}
        return self._domain_list

    def remove_record_by_sub_domain(self, domain, sub_domain, type):
        sub_domain = check_sub_domain(domain, sub_domain)
        record_list = self.get_record_list(domain, type)
        record_existent = next((item for item in record_list if item["name"] == sub_domain), None)
        if record_existent is None:
            return
        else:
            record_id = record_existent["id"]
            self.remove_record(domain, record_id)
        return record_id

    def ensure_record(self, domain, sub_domain, type, value):
        sub_domain = check_sub_domain(domain, sub_domain)

        record_list = self.get_record_list(domain, type)
        record_existent = next((item for item in record_list if item["name"] == sub_domain), None)
        if record_existent is None:
            record_created = self.add_record(domain, sub_domain, type, value)
            record_id = record_created["record"]["id"]
        else:
            record_id = record_existent["id"]
            self.modify_record(domain, record_id, type, value)
        return record_id
