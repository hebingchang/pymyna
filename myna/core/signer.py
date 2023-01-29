import hashlib
import typing

from cryptography.hazmat.bindings._openssl import ffi
from cryptography.hazmat.primitives import _serialization, hashes, serialization
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils, AsymmetricSignatureContext
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPrivateNumbers, RSAPublicKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder, PKCS7Options
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.univ import Sequence, ObjectIdentifier, Any, OctetString, Null
from pyasn1.codec.der.encoder import encode

from myna.api.jpki_ap import JPKIAPReader
from myna.core.reader import MyNumberCardReader


class AlgorithmIdentifier(Sequence):
    componentType = NamedTypes(
        NamedType('algorithm', ObjectIdentifier()),
        OptionalNamedType('parameters', Any()),
    )


class DigestInfo(Sequence):
    componentType = NamedTypes(
        NamedType('identifier', AlgorithmIdentifier()),
        NamedType('digest', OctetString()),
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CardPrivateKey(RSAPrivateKey):
    def signer(self, padding: AsymmetricPadding, algorithm: hashes.HashAlgorithm) -> AsymmetricSignatureContext:
        pass

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        pass

    def key_size(self) -> int:
        pass

    def public_key(self) -> RSAPublicKey:
        pass

    def sign(self, data: bytes, padding: AsymmetricPadding,
             algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm]) -> bytes:
        pass

    def private_numbers(self) -> RSAPrivateNumbers:
        pass

    def private_bytes(self, encoding: _serialization.Encoding, format: _serialization.PrivateFormat,
                      encryption_algorithm: _serialization.KeySerializationEncryption) -> bytes:
        pass


algorithm_identifiers = {
    hashlib.sha1: '6.5.43.14.3.2.26',
    hashlib.sha256: '6.9.96.134.72.1.101.3.4.2.1',
    hashlib.sha384: '6.9.96.134.72.1.101.3.4.2.2',
    hashlib.sha512: '6.9.96.134.72.1.101.3.4.2.3',
}


def build_digest_info(algo, digest):
    assert algo in algorithm_identifiers, 'Unsupported hash algorithm.'
    digest_info = DigestInfo()
    identifier = AlgorithmIdentifier()
    identifier['algorithm'] = algorithm_identifiers[algo]
    identifier['parameters'] = Null('')
    digest_info['identifier'] = identifier
    digest_info['digest'] = digest

    return list(encode(digest_info))


def sign(data: bytes, jpki_ap: JPKIAPReader, algo):
    private_key = CardPrivateKey()
    options = [PKCS7Options.DetachedSignature]
    PKCS7SignatureBuilder().set_data(data).add_signer(
        jpki_ap.get_sign_cert(), private_key, hashes.SHA256()
    ).sign(
        serialization.Encoding.SMIME, options
    )

    # TODO: implement CardPrivateKey class
