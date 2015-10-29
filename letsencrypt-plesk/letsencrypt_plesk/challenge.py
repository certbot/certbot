"""PleskChallenge"""
import logging
import os

from letsencrypt import errors

from letsencrypt_plesk import api_client

logger = logging.getLogger(__name__)


class PleskChallenge(object):
    """Class performs challenges within the Plesk configurator."""

    def __init__(self, plesk_api_client):
        self.plesk_api_client = plesk_api_client
        self.www_root = None
        self.ftp_login = None
        self.verify_path = None
        self.full_path = None

    def perform(self, achall):
        """Perform a challenge on Plesk."""
        response, validation = achall.gen_response_and_validation(False)
        self._put_validation_file(
            domain=achall.domain,
            file_path=response.URI_ROOT_PATH,
            file_name=achall.chall.encode("token"),
            content=validation.json_dumps())
        return response

    def _put_validation_file(self, domain, file_path, file_name, content):
        """Put file to the domain with validation content"""
        request = {'packet': {'site': {'get': [
            {'filter': {'name': domain}},
            {'dataset': {'hosting': {}}},
        ]}}}
        response = self.plesk_api_client.request(request)

        api_result = response['packet']['site']['get']['result']
        if 'ok' != api_result['status']:
            error_text = str(api_result['errtext'])
            raise errors.DvAuthError('Site get failure: %s' % error_text)

        hosting_props = api_result['data']['hosting']['vrt_hst']['property']
        self.www_root = next(
            x['value'] for x in hosting_props if 'www_root' == x['name'])
        self.ftp_login = next(
            x['value'] for x in hosting_props if 'ftp_login' == x['name'])

        self.verify_path = os.path.join(self.www_root, file_path)
        self.full_path = os.path.join(self.www_root, file_path, file_name)
        tmp_path = os.tempnam()
        with open(tmp_path, 'w') as f:
            f.write(str(content))
            f.close()
        try:
            self.plesk_api_client.filemng(
                [self.ftp_login, "mkdir", self.verify_path, "-p"])
            self.plesk_api_client.filemng(
                [self.ftp_login, "cp2perm", tmp_path, self.full_path, "0644"])
        finally:
            os.unlink(tmp_path)

    def cleanup(self, unused_achall):
        """Remove validation file and directories."""
        try:
            if self.www_root and self.ftp_login:
                self.plesk_api_client.filemng(
                    [self.ftp_login, "rm", self.full_path])

                while self._is_sub_path(self.verify_path, self.www_root):
                    self.plesk_api_client.filemng(
                        [self.ftp_login, "rmdir", self.verify_path])
                    self.verify_path = os.path.dirname(self.verify_path)
        except api_client.PleskApiException as e:
            logger.debug(str(e))

    @staticmethod
    def _is_sub_path(child, parent):
        child = os.path.realpath(child)
        parent = os.path.join(os.path.realpath(parent), '')
        common = os.path.commonprefix([child, parent])
        return common == parent and not child == parent
