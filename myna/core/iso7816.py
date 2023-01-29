from enum import IntFlag, Enum


class FileSelectionReferenceControl(Enum):
    SelectEFUnderCurrentDF = 0b00000010
    SelectByDFName = 0b00000100


class FileSelectionOptions(IntFlag):
    FirstOccurrence = 0b00000000
    LastOccurrence = 0b00000001
    NextOccurrence = 0b00000010
    PreviousOccurrence = 0b00000011

    FCI = 0b00000000
    FCP = 0b00000100
    FMD = 0b00001000
    Other = 0b00001100


class SecurityReference(Enum):
    GlobalReferenceData = 0b00000000
    SpecificReferenceData = 0b10000000


class MifareReader:
    _connection = None

    def __init__(self, connection):
        self._connection = connection

    def _select_visual_ap(self):
        # SELECT FILE: 券面AP
        _, sw1, sw2 = self._select_file(
            [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08],
            FileSelectionReferenceControl.SelectByDFName,
            FileSelectionOptions.FirstOccurrence | FileSelectionOptions.Other,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f'SELECT FILE error: {sw1} {sw2}.'

    def _select_file(self, file: list[int], p1: FileSelectionReferenceControl, p2: FileSelectionOptions):
        cls = 0x00
        ins = 0xa4
        return self._connection.transmit([cls, ins, p1.value, p2.value, len(file), *file])

    def _select_df(self, file: list[int]):
        _, sw1, sw2 = self._select_file(
            file,
            FileSelectionReferenceControl.SelectByDFName,
            FileSelectionOptions.FirstOccurrence | FileSelectionOptions.Other,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f'SELECT FILE error: {sw1} {sw2}.'

    def _select_ef(self, file: list[int]):
        _, sw1, sw2 = self._select_file(
            file,
            FileSelectionReferenceControl.SelectEFUnderCurrentDF,
            FileSelectionOptions.FirstOccurrence | FileSelectionOptions.Other,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f'SELECT FILE error: {sw1} {sw2}.'

    def _verify(self, data: list[int], p2: SecurityReference):
        cls = 0x00
        ins = 0x20
        p1 = 0x00
        return self._connection.transmit([cls, ins, p1, p2.value, len(data), *data])

    def _read_binary(self, offset: int, length: int, length_bytes=1):
        assert 0 <= offset < 32768, 'Offset should between 0-32767.'
        assert 0 <= length < (1 << (length_bytes * 8)), f'Length should between 0-{(1 << (length_bytes * 8)) - 1}.'
        cls = 0x00
        ins = 0xb0

        lb = list()
        for i in range(length_bytes):
            lb.append((length >> (8 * (length_bytes - i - 1))) % (1 << (8 * (length_bytes - i))))

        return self._connection.transmit([cls, ins, offset >> 8, offset % 256, *lb])

    def _compute_digital_signature(self):
        cls = 0x00
        ins = 0x2a
        p1 = 0x00
        p2 = 0x80
        return self._connection.transmit([cls, ins, p1, p2, len(file), *file])
