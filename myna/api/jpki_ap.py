from datetime import date
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from myna.core.iso7816 import SecurityReference, MifareReader


class JPKIAPReader(MifareReader):
    def __init__(self, connection):
        super().__init__(connection)
        self.check_ap()

    def select_jpki_ap(self):
        # SELECT FILE: 公的個人認証AP
        self._select_df([0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01])

    def check_ap(self):
        # is JPKI AP?
        self.select_jpki_ap()
        token = self.get_token()
        assert token == 'JPKIAPICCTOKEN2', 'Invalid AP! Maybe not a My Number Card?'

    def get_token(self):
        # SELECT FILE: JPKI TOKEN
        self._select_ef([0x00, 0x06])
        token, sw1, sw2 = self._read_binary(0, 0x20)
        assert sw1 == 0x90 and sw2 == 0x00, f'GET TOKEN error: {sw1} {sw2}.'
        return ''.join(chr(c) for c in token).rstrip()

    def verify_pin(self, auth_pin: str, sign_pin: str):
        assert len(auth_pin) == 4, 'Auth PIN should contain exactly 4 digits.'
        assert auth_pin.isdigit(), 'Auth PIN should only contain digits.'
        assert 6 <= len(sign_pin) <= 16, 'Sign PIN should contain exactly 4 digits.'
        assert sign_pin.isalnum(), 'Sign PIN should only contain digits and alphabets.'

        # SELECT FILE: JPKI AP (DF)
        self.select_jpki_ap()

        # SELECT FILE: JPKI 認証用PIN (EF)
        self._select_ef([0x00, 0x18])

        # VERIFY: JPKI 認証用PIN
        _, sw1, sw2 = self._verify(
            [ord(c) for c in auth_pin],
            SecurityReference.SpecificReferenceData,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f'VERIFY error: {sw1} {sw2}.'

        # SELECT FILE: JPKI 署名用PIN (EF)
        self._select_ef([0x00, 0x1B])

        # VERIFY: JPKI 署名用PIN
        _, sw1, sw2 = self._verify(
            [ord(c) for c in sign_pin.upper()],
            SecurityReference.SpecificReferenceData,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f'VERIFY error: {sw1} {sw2}.'

    def _get_cert(self, ef_id: list[int]):
        assert len(ef_id) == 2

        # SELECT FILE: 証明書
        self._select_ef(ef_id)

        # READ BINARY: 最初の4バイトを読み取り、証明書のバイト長を得る
        bin_len, sw1, sw2 = self._read_binary(0, 4)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'
        assert len(bin_len) == 4, 'Get binary length error: no data.'

        # READ BINARY: 証明書全体のデータを読み取る
        bin_data, sw1, sw2 = self._read_binary(0, (bin_len[2] << 8) + bin_len[3] + 4, length_bytes=3)
        assert sw1 == 0x90 and sw2 == 0x00, f'READ BINARY error: {sw1} {sw2}.'

        return x509.load_der_x509_certificate(bytes(bin_data))

    def get_auth_cert(self):
        return self._get_cert([0x00, 0x0A])

    def get_auth_ca_cert(self):
        return self._get_cert([0x00, 0x0B])

    def get_sign_cert(self):
        return self._get_cert([0x00, 0x01])

    def get_sign_ca_cert(self):
        return self._get_cert([0x00, 0x02])
