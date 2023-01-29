import base64
import logging
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Certificate

from myna.utils import constants

logger = logging.getLogger('certificate')


@dataclass
class ASN1RSAPublicKey:
    exp: int = field(metadata={'tag': 16})
    n: int = field(metadata={'tag': 17})


class CommonCertificate:
    aki: bytes
    ski: bytes
    pubkey: bytes
    signature: bytes

    def __init__(self, keys: bytes, signature: bytes):
        assert len(keys) == 297, 'Bad keys length.'
        self.aki = keys[0:16]
        self.ski = keys[16:32]
        self.pubkey = keys[32:]
        self.signature = signature

    def verify_signature(self):
        # 1. get public key pem with aki
        # 2. verify (aki || ski || pubkey) signature with SHA256withRSA
        aki = self.aki.hex()
        if aki not in constants.text_pubkeys:
            return False

        pubkey = serialization.load_der_public_key(base64.b64decode(constants.text_pubkeys[aki]))
        pubkey.verify(
            self.signature,
            self.aki + self.ski + self.pubkey,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        logger.debug('signature verified ok.')


def pretty_print_certificate(cert: Certificate):
    print(f'SerialNumber: {cert.serial_number}')
    print(f'Subject: {cert.subject}')
    print(f'Issuer: {cert.issuer}')
    print(f'NotBefore: {cert.not_valid_before}')
    print(f'NotAfter: {cert.not_valid_after}')
