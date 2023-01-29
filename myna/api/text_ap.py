import hashlib
import logging
from dataclasses import dataclass, field
from datetime import date
from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from myna.core.certificate import CommonCertificate, ASN1RSAPublicKey
from myna.core.iso7816 import SecurityReference, MifareReader
from myna.utils.asn1_helper import asn1_decode_with_params, asn1_decode_raw, asn1_decode

logger = logging.getLogger('text_ap')


@dataclass
class TextBasicInfo:
    ap_info: bytes = field(metadata={'tag': 65})
    key_id: bytes = field(metadata={'tag': 66})


class Gender(Enum):
    Male = 1
    Female = 2
    Other = 9


@dataclass
class TextMyNumber:
    my_number: str
    _raw: bytes

    def __str__(self):
        return f'MyNumber({self.my_number})'

    def __repr__(self):
        return f'MyNumber({self.my_number})'

    def verify_digest(self, digest: bytes):
        m = hashlib.sha256()
        m.update(self._raw)

        assert digest == m.digest(), 'Bad my_number digest.'
        logger.debug('my_number verified ok.')


@dataclass
class TextAttrs:
    header: bytes = field(metadata={'tag': 33})
    name: str = field(metadata={'tag': 34})
    birthday: date = field(metadata={'tag': 36})
    gender: Gender = field(metadata={'tag': 37})
    address: str = field(metadata={'tag': 35})
    _raw: bytes = field(metadata={'tag': -1})

    def __str__(self):
        return f'TextAttrs({self.name})'

    def __repr__(self):
        return f'TextAttrs({self.name})'

    def verify_digest(self, digest: bytes):
        m = hashlib.sha256()
        m.update(self._raw[11:])  # asn1(name) + asn1(address) + asn1(birthday) + asn1(gender)

        assert digest == m.digest(), 'Bad attributes digest.'
        logger.debug('attributes verified ok.')


@dataclass
class TextSignature:
    _raw: bytes = field(metadata={'tag': -1})
    my_number_digest: bytes = field(metadata={'tag': 49})
    attrs_digest: bytes = field(metadata={'tag': 50})
    signature: bytes = field(metadata={'tag': 51})

    @property
    def all_digest(self):
        return self._raw[:70]  # asn1(my_number_digest) + asn1(attrs_digest)

    def __str__(self):
        return 'TextSignature(signatures)'

    def __repr__(self):
        return 'TextSignature(signatures)'


@dataclass
class TextCertificate(CommonCertificate):
    keys: bytes = field(metadata={'tag': 78})
    signature: bytes = field(metadata={'tag': 55})

    def __init__(self, keys: bytes, signature: bytes):
        super().__init__(keys, signature)

    @property
    def public_key(self):
        pubkey = asn1_decode(self.pubkey, ASN1RSAPublicKey)
        return RSAPublicNumbers(pubkey.exp, pubkey.n).public_key()

    def __str__(self):
        return 'TextCertificate(certificates)'

    def __repr__(self):
        return 'TextCertificate(certificates)'


@dataclass
class TextAP:
    my_number: TextMyNumber
    attributes: TextAttrs
    signature: TextSignature
    certificate: TextCertificate
    basic_info: TextBasicInfo

    def verify_signature(self):
        if self.my_number is None:
            raise Exception('my_number has not been read.')
        if self.attributes is None:
            raise Exception('attributes has not been read.')
        if self.certificate is None:
            raise Exception('certificate has not been read.')
        if self.signature is None:
            raise Exception('signature has not been read.')

        # validate my_number
        self.my_number.verify_digest(self.signature.my_number_digest)

        # validate attributes
        self.attributes.verify_digest(self.signature.attrs_digest)

        # validate certificate
        self.certificate.verify_signature()

        # validate signature
        pubkey = self.certificate.public_key
        pubkey.verify(
            self.signature.signature,
            self.signature.all_digest,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        logger.debug('all text_ap verified ok.')


class TextAPReader(MifareReader):
    def select_text_ap(self):
        # SELECT FILE: 券面入力補助AP (DF)
        self._select_df([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08])

    def verify_pin(self, auth_pin):
        assert len(auth_pin) == 4, 'Auth PIN should contain exactly 4 digits.'
        assert auth_pin.isdigit(), 'Auth PIN should only contain digits.'

        # SELECT FILE: 券面入力補助AP (DF)
        self.select_text_ap()

        # SELECT FILE: 券面入力補助用PIN (EF)
        self._select_ef([0x00, 0x11])

        # VERIFY: 券面入力補助用PIN
        _, sw1, sw2 = self._verify(
            [ord(c) for c in auth_pin],
            SecurityReference.SpecificReferenceData,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f'VERIFY error: {sw1} {sw2}.'

    def get_all_files(self, pin: str) -> TextAP:
        self.verify_pin(pin)
        return TextAP(
            my_number=self.get_my_number(),
            attributes=self.get_attrs(),
            signature=self.get_signature(),
            certificate=self.get_certificate(),
            basic_info=self.get_basic_info(),
        )

    def get_my_number(self) -> TextMyNumber:
        # SELECT FILE: My Number (EF)
        self._select_ef([0x00, 0x01])

        # READ BINARY
        bin_data, sw1, sw2 = self._read_binary(0, 17)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'

        # ASN.1 decode
        value = asn1_decode_raw(bin_data, 16)
        return TextMyNumber(my_number=value.decode(), _raw=bytes(bin_data))

    def get_signature(self) -> TextSignature:
        # SELECT FILE: My Number (EF)
        self._select_ef([0x00, 0x03])

        # READ BINARY
        bin_data, sw1, sw2 = self._read_binary(0, 336, 3)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'
        assert len(bin_data) == 336, 'Bad signature length.'

        # ASN.1 decode
        return asn1_decode_with_params(bin_data, TextSignature, 48)

    def get_attrs(self) -> TextAttrs:
        # SELECT FILE: 基本4情報 (EF)
        self._select_ef([0x00, 0x02])

        # READ BINARY: 基本4情報の読み取り（3バイト目のデータ長のみ）
        bin_len, sw1, sw2 = self._read_binary(2, 1)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'
        assert len(bin_len) == 1, 'Get binary length error: no data.'

        # READ BINARY: 基本4情報の読み取り（3 + bin_len）
        bin_data, sw1, sw2 = self._read_binary(0, 3 + bin_len[0])
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'

        return asn1_decode_with_params(bin_data, TextAttrs, 32)

    def get_certificate(self) -> TextCertificate:
        # SELECT FILE
        self._select_ef([0x00, 0x04])

        # READ BINARY
        bin_data, sw1, sw2 = self._read_binary(0, 568, length_bytes=3)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'
        assert len(bin_data) == 568, f'Bad certificate length.'

        return asn1_decode_with_params(bin_data, TextCertificate, 33)

    def get_basic_info(self) -> TextBasicInfo:
        # SELECT FILE
        self._select_ef([0x00, 0x05])

        # READ BINARY
        bin_data, sw1, sw2 = self._read_binary(0, 256, length_bytes=3)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'
        assert len(bin_data) == 256, f'Bad basic info length.'

        basic_info = asn1_decode_with_params(bin_data, TextBasicInfo, 64)
        assert len(basic_info.ap_info) == 4, 'Bad APInfo length'
        assert len(basic_info.key_id) == 16, 'Bad KeyID length'

        return basic_info
