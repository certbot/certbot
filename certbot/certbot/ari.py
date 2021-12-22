from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509 import ocsp
import josepy as jose
import requests

from acme.messages import RenewalInfo
from certbot.interfaces import RenewableCert  # pylint: disable=unused-import

class AriChecker(object):
    """This class checks ACME Renewal Info."""

    def __init__(self, ari_endpoint: string) -> None:
        self.ari_endpoint = ari_endpoint.rstrip('/')

    def _compute_path(self, cert: RenewableCert, issuer: RenewableCert) -> bool:
        # Rather than compute the serial, issuer key hash, and issuer name hash
        # ourselves, we instead build an OCSP Request and extract those fields.
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        ocspRequest = builder.build()

        # Construct the ARI path from the OCSP CertID sequence.
        key_hash = ocspRequest.issuer_key_hash.hex()
        name_hash = ocspRequest.issuer_name_hash.hex()
        serial = hex(ocspRequest.serial_number)[2:]
        path = f"{key_hash}/{name_hash}/{serial}"

        return '/'.join(self.ari_endpoint, path)

    def _get_ari(self, cert: RenewableCert, issuer: RenewableCert) -> RenewalInfo:
        url = self._compute_path(cert, issuer)
        try:
            response = request.get(url)
        except requests.exceptions.RequestException:
            return False
        if response.status_code != 200:
            return False

        try:
            json = response.json()
        except requests.exceptions.JSONDecodeError:
            return False

        try:
            ari = RenewalInfo.from_json(json)
        except jose.errors.DeserializationError:
            return False

        return ari

    def should_renew(self, cert: RenewableCert, issuer: RenewableCert) -> bool:
        ari = self._get_ari(cert, issuer)
        window_secs = ari.window.end + datetime.timedelta(seconds=1) - ari.window.start
        rand_offset = random.randrange(int(window_secs.total_seconds()))
        instant = ari.window.start + datetime.timedelta(seconds=rand_offset)
        return instant <= datetime.datetime.now()

    def should_renew_by_paths(self, cert_path: str, chain_path: str) -> bool:
        with open(cert_path, 'rb') as file_handler:
            cert = x509.load_pem_x509_certificate(file_handler.read(), default_backend())
        with open(chain_path, 'rb') as file_handler:
            issuer = x509.load_pem_x509_certificate(file_handler.read(), default_backend())
        return self.should_renew(cert, issuer)
