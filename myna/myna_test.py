import logging
import os

from myna.core.reader import MyNumberCardReader

import unittest


class TestMyNaMethods(unittest.TestCase):
    reader = MyNumberCardReader()
    auth_pin = os.getenv('AUTH_PIN')
    sign_pin = os.getenv('SIGN_PIN')

    def test_text_ap(self):
        text_ap = self.reader.select_text_ap()
        text_ap_files = text_ap.get_all_files(self.auth_pin)
        text_ap_files.verify_signature()

    def test_jpki_ap(self):
        jpki_ap = self.reader.select_jpki_ap()
        jpki_ap.verify_pin(self.auth_pin, self.sign_pin)

    def test_visual_ap(self):
        pass


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG)
    unittest.main()
