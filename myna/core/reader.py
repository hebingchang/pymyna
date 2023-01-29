from smartcard.System import readers

from myna.api.jpki_ap import JPKIAPReader
from myna.api.text_ap import TextAPReader


class MyNumberCardReader:
    _connection = None
    _jpki_ap = None
    _text_ap = None

    def __init__(self):
        r = readers()
        self._connection = r[0].createConnection()
        self._connection.connect()

        self._jpki_ap = JPKIAPReader(self._connection)
        self._text_ap = TextAPReader(self._connection)

    def select_jpki_ap(self):
        self._jpki_ap.select_jpki_ap()
        return self._jpki_ap

    def select_text_ap(self):
        self._text_ap.select_text_ap()
        return self._text_ap
