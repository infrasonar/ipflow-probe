import struct
from typing import List
from .field import Field


class DataTemplate:
    __slots__ = (
        '_fmt',
        'length',
        'fields',
        'index',
        'source_uptime',
    )

    def __init__(self, fmt: str, length: int, fields: List[Field],
                 index: List[int], source_uptime: int):
        self._fmt = struct.Struct(fmt)
        self.fields = fields
        self.index = index
        self.length = length
        self.source_uptime = source_uptime
