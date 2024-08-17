from .field_type import FIELD_TYPE_FMT
from .field_type import FieldType


class Field:
    __slots__ = (
        '_fmt',
        'id',
        'length',
    )

    def __init__(self, field_id: int, length: int):
        self._fmt = FIELD_TYPE_FMT.get(field_id, f'{length}s')
        self.id = field_id
        self.length = length

    @property
    def name(self) -> str:
        # used for serializing flows, unknown fields will be dropped later
        try:
            return FieldType(self.id).name.lower()
        except Exception:
            # field_id can either be unknown or purposely missing from the enum
            # as we only expect a subset of the available metrics
            return None
