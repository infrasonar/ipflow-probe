import struct
from typing import Union
from .field import Field
from .field_type import FieldType


class DataTemplate:
    __slots__ = (
        'fmt',
        'length',
        'fields',
        'index',
        'source_uptime',
    )

    def __init__(self, fmt: str, length: int, fields: list[Field],
                 index: list[Union[int, FieldType, None]], source_uptime: int):
        self.fmt = struct.Struct(fmt)
        self.fields = fields
        self.index = index
        self.length = length
        self.source_uptime = source_uptime
