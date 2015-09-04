"""PleskChallenge"""
import itertools
import logging
import os

from letsencrypt import errors
from letsencrypt.plugins import common

logger = logging.getLogger(__name__)


class PleskChallenge(object):
    """Class performs challenges within the Plesk configurator."""

    def __init__(self, configurator):
        self.configurator = configurator

    def perform(self, achall):
        """Perform a challenge on Plesk."""
        response, validation = achall.gen_response_and_validation(False)
        file_name = achall.chall.encode("token")
        self._put_validation_file(achall.domain, response.URI_ROOT_PATH, file_name, validation.to_json())
        return response

    def _put_validation_file(self, domain, file_path, file_name, content):
        """Put file to the domain with validation content"""
        request = {'packet': {'site': {'get': {'filter': {'name': domain}, 'dataset': {'hosting': ''}}}}}
        response = self.configurator.plesk_api_client.request(request)

        result = response['packet']['site']['get']['result']
        if not (result and 'ok' == result['status']):
            raise errors.DvAuthError("Site get failure: " + str(result['errtext']))

        hosting_props = result['data']['hosting']['vrt_hst']['property']
        self.www_root = next(x['value'] for x in hosting_props if 'www_root' == x['name'])
        self.ftp_login = next(x['value'] for x in hosting_props if 'ftp_login' == x['name'])

        self.verify_path = os.path.join(self.www_root, file_path)
        self.full_path = os.path.join(self.www_root, file_path, file_name)
        tmp_path = os.tempnam()
        with open(tmp_path, 'w') as f:
            f.write(str(content))
            f.close()
        try:
            self.configurator.plesk_api_client.filemng([self.ftp_login, "mkdir", self.verify_path, "-p"])
            self.configurator.plesk_api_client.filemng([self.ftp_login, "cp2perm", tmp_path, self.full_path, "0644"])
        finally:
            os.unlink(tmp_path)

    def cleanup(self, achall):
        """Remove validation file and directories."""
        try:
            if self.www_root and self.ftp_login:
                self.configurator.plesk_api_client.filemng([self.ftp_login, "rm", self.full_path])
                www_root = os.path.join(os.path.realpath(self.www_root), '')
                verify_path = os.path.realpath(self.verify_path)
                while os.path.commonprefix([verify_path, www_root]) == www_root and not verify_path == www_root:
                    self.configurator.plesk_api_client.filemng([self.ftp_login, "rmdir", verify_path])
                    verify_path = os.path.dirname(verify_path)
        except Exception as e:
            logger.debug(str(e))
