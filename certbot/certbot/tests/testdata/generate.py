from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509 import Certificate, CertificateSigningRequest
from cryptography.x509.oid import NameOID

import datetime
from typing import Optional, Any

issuer_key = ec.generate_private_key(ec.SECP256R1())
rsa2048_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

p256_key=ec.generate_private_key(ec.SECP256R1())
p384_key=ec.generate_private_key(ec.SECP384R1())

# Define certificate subject
issuer_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer for Certbot"),
])

issuer_cert = x509.CertificateBuilder(
    issuer_name=issuer_name,
    subject_name=issuer_name,
    public_key=issuer_key.public_key(),
    serial_number=x509.random_serial_number(),
    not_valid_before=datetime.datetime(2005, 2, 25, 0, 0, 0),
    not_valid_after=datetime.datetime(2055, 2, 25, 0, 0, 0),
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),
    critical=False,
).sign(
    private_key=issuer_key,
    algorithm=hashes.SHA256(),
)

def make_ee_cert(sans: list[str], common_name: Optional[str] = None, key: Optional[Any] = None) -> Certificate:
    subject_name=x509.Name([])
    if common_name is not None:
        subject_name=x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

    if key is None:
        key = rsa2048_key

    return x509.CertificateBuilder(
        issuer_name=issuer_name,
        subject_name=subject_name,
        public_key=key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime(2014, 12, 11, 22, 34, 45),
        not_valid_after=datetime.datetime(2014, 12, 18, 22, 34, 45),
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    ).sign(
        private_key=issuer_key,
        algorithm=hashes.SHA256(),
    )

rsa2048_cert = make_ee_cert(["example.com"])
rsa2048_cert_www = make_ee_cert(["example.com", "www.example.com"])
# See GetNamesFromTestCert::test_common_name_sans_order
cert_5sans = make_ee_cert(["a.example.com", "b.example.com", "c.example.com", "d.example.com", "example.com"], "example.com")
p256_cert = make_ee_cert([], key = p256_key)

def make_csr(names: list[str], common_name: Optional[str] = None) -> CertificateSigningRequest:
    x509names = [x509.DNSName(n) for n in names]
    subject_name = x509.Name([])
    if common_name is not None:
        subject_name=x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    return x509.CertificateSigningRequestBuilder(
        subject_name=subject_name
    ).add_extension(
        x509.SubjectAlternativeName(x509names),
        critical=False,
    ).sign(
        private_key=rsa2048_key,
        algorithm=hashes.SHA256(),
    )

csr_example = make_csr(["example.com"])
csr_example_www = make_csr(["example.com", "www.example.com"])
csr_nonames = make_csr([])
csr_nosans = make_csr([], "example.com")
csr_6sans = make_csr(["example.com", "example.org", "example.net", "example.info",
        "subdomain.example.com", "other.subdomain.example.com"])

def write_key(filename: str, key: Any) -> None:
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def write_cert(filename: str, cert: Certificate) -> None:
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def write_csr(filename: str, csr: CertificateSigningRequest) -> None:
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

write_cert("issuer_cert.pem", issuer_cert)
write_key("rsa2048_key.pem", rsa2048_key)
# We lie and write 2048 bit stuff to the old "512" names. The tests don't care.
write_key("rsa512_key.pem", rsa2048_key)
write_cert("cert_2048.pem", rsa2048_cert)
write_cert("cert_512.pem", rsa2048_cert)
write_cert("cert-san_512.pem", rsa2048_cert_www)
write_cert("cert-5sans_512.pem", cert_5sans)
write_cert("cert-nosans_nistp256.pem", p256_cert)

write_key("nistp256_key.pem", p256_key)
write_key("ec_secp384r1_key.pem", p384_key)

write_csr("csr_512.pem", csr_example)
with open("csr_512.der", "wb") as f:
    f.write(csr_example.public_bytes(serialization.Encoding.DER))
write_csr("csr-san_512.pem", csr_example_www)
write_csr("csr-nonames_512.pem", csr_nonames)
write_csr("csr-nosans_512.pem", csr_nosans)
write_csr("csr-6sans_512.pem", csr_6sans)

with open("cert_fullchain_2048.pem", "wb") as f:
    f.write(rsa2048_cert.public_bytes(serialization.Encoding.PEM))
    f.write(issuer_cert.public_bytes(serialization.Encoding.PEM))
