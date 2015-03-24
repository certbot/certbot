"""Networking for ACME protocol v02."""
import httplib
import logging

import requests

from letsencrypt.acme import jose
from letsencrypt.acme import messages2


class Network(object):
    """ACME networking.

    :ivar str new_reg_uri: Location of new-reg
    :ivar key: `.JWK` (private)
    :ivar alg: `.JWASignature`

    """

    def __init__(self, new_reg_uri, key, alg=jose.RS256):
        self.new_reg_uri = new_reg_uri
        self.key = key
        self.alg = alg

    def _wrap_in_jws(self, data):
        dumps = data.json_dumps()
        logging.debug('Serialized JSON: %s', dumps)
        return jose.JWS.sign(
            payload=dumps, key=self.key, alg=self.alg).json_dumps()

    def _post(self, uri, data):
        logging.debug('Sending data: %s', data)
        response = requests.post(uri, data)
        logging.debug('Received response %s: %s', response, response.text)
        return response

    def register(self, contact=messages2.Registration._fields['contact'].default):
        new_reg = messages2.Registration(contact=contact)
        response = self._post(self.new_reg_uri, self._wrap_in_jws(new_reg))
        assert response.status_code == httplib.CREATED  # TODO: handle errors
        regr = messages2.RegistrationResource(
            body=messages2.Registration.from_json(response.json()),
            uri=response.headers['location'],
            new_authz_uri=response.links['next']['url'],
        )
        assert regr.body.key == self.key.public()
        return regr

    def request_challenges(self, identifier, regr):
        """Request challenges.

        :param identifier: Identifier to be challenged.
        :type identifier: `.messages2.Identifier`

        :pram regr: Registration resource.
        :type regr: `.RegistrationResource`

        """
        new_authz = messages2.Authorization(identifier=identifier)
        response = self._post(regr.new_authz_uri, self._wrap_in_jws(new_authz))
        assert response.status_code == httplib.CREATED  # TODO: handle errors
        authzr = messages2.AuthorizationResource(
            body=messages2.Authorization.from_json(response.json()),
            uri=response.headers['location'],
            new_cert_uri=response.links['next']['url'])
        assert authzr.body.key == self.key.public()
        return authzr
