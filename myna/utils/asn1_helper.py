from dataclasses import fields
from datetime import date
from enum import Enum

import asn1


def asn1_decode_raw(data, root_tag: int) -> bytes:
    decoder = asn1.Decoder()
    decoder.start(bytes(data))
    tag, value = decoder.read()
    assert tag.nr == root_tag, f'Bad ASN.1 tag: {tag}.'

    return value


def asn1_decode(data, cls):
    decoder = asn1.Decoder()
    decoder.start(data if type(data) == bytes else bytes(data))

    field_id_map = dict()
    field_name_map = dict()

    for _field in fields(cls):
        if 'tag' in _field.metadata:
            field_id_map[_field.metadata['tag']] = _field
            if _field.metadata['tag'] == -1:
                # _raw field
                field_name_map[_field.name] = data

    while not decoder.eof():
        tag, value = decoder.read()
        if tag.nr in field_id_map:
            _field = field_id_map[tag.nr]
            if _field.type == date:
                field_name_map[_field.name] = date(int(value[0:4]), int(value[4:6]), int(value[6:8]))
            elif issubclass(_field.type, Enum):
                field_name_map[_field.name] = _field.type(int(value))
            elif _field.type == str:
                field_name_map[_field.name] = value.decode()
            elif _field.type == int:
                field_name_map[_field.name] = int.from_bytes(value, "big")
            else:
                field_name_map[_field.name] = value

    return cls(**field_name_map)


def asn1_decode_with_params(data, cls, root_tag: int):
    decoder = asn1.Decoder()
    decoder.start(bytes(data))
    tag, value = decoder.read()
    assert tag.nr == root_tag, f'Bad ASN.1 tag: {tag}.'
    return asn1_decode(value, cls)
