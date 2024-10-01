import struct
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Iterator, Union, Any
from .field import Field
from .field_type import FIELD_TYPE_FUNC
from .field_type import FieldType
from .template import DataTemplate


V5_TEMPLATE_KEY = None, None, None
V5_TEMPLATE_FMT = '>4s4s4sHHLLLLHH2sBBB3s4s'
V5_TEMPLATE_SIZE = struct.calcsize(V5_TEMPLATE_FMT)
V5_FIELDS = [
    Field(FieldType.IPV4_SRC_ADDR.value, 4),
    Field(FieldType.IPV4_DST_ADDR.value, 4),
    Field(FieldType.IPV4_NEXT_HOP.value, 4),
    Field(FieldType.INPUT_SNMP.value, 2),
    Field(FieldType.OUTPUT_SNMP.value, 2),
    Field(FieldType.IN_PKTS.value, 4),
    Field(FieldType.IN_BYTES.value, 4),
    Field(FieldType.FIRST_SWITCHED.value, 4),
    Field(FieldType.LAST_SWITCHED.value, 4),
    Field(FieldType.L4_SRC_PORT.value, 2),
    Field(FieldType.L4_DST_PORT.value, 2),
    Field(FieldType.PROTOCOL.value, 1),
    Field(FieldType.TOS.value, 1),
    Field(FieldType.TCP_FLAGS.value, 1),
]

DataTemplateKey = Any  # TODO v5 key should should be also tuple[str, int, int]
flowset_templates: dict[DataTemplateKey, DataTemplate] = {
    V5_TEMPLATE_KEY: DataTemplate(
        V5_TEMPLATE_FMT,
        V5_TEMPLATE_SIZE,
        V5_FIELDS,
        [f.id for f in V5_FIELDS],
        0,  # uptime not used for v5 packets
    )
}


class Flow:
    __slots__ = (
        'template',
        'values',
    )

    def __init__(self, template: DataTemplate, values: tuple[bytes, ...]):
        self.template = template
        self.values = values

    def serialize(self) -> dict:
        '''
        returns a serialized representation
        fields without a formatter are omitted from the result
        '''
        fields = [f for f in self.template.fields if f.fmt]
        return {
            f.name: FIELD_TYPE_FUNC.get(f.id, lambda val: val)(val)
            for f, val in zip(fields, self.values)
        }

    def test_address(
        self,
        address: Union[IPv4Address, IPv6Address]
    ) -> bool:
        fields_idx = self.template.index
        for ft in (
            FieldType.IPV4_DST_ADDR,
            FieldType.IPV4_NEXT_HOP,
            FieldType.IPV4_SRC_ADDR,
        ):
            if ft.value in fields_idx:
                addr = IPv4Address(self.values[fields_idx.index(ft.value)])
                if addr == address:
                    return True

        for ft in (
            FieldType.IPV6_DST_ADDR,
            FieldType.IPV6_NEXT_HOP,
            FieldType.IPV6_SRC_ADDR,
        ):
            if ft.value in fields_idx:
                addr = IPv6Address(self.values[fields_idx.index(ft.value)])
                if addr == address:
                    return True
        return False

    def test_network(
        self,
        network: Union[IPv4Network, IPv6Network]
    ) -> Iterator[Union[IPv4Address, IPv6Address]]:
        fields_idx = self.template.index
        for ft in (
            FieldType.IPV4_DST_ADDR,
            FieldType.IPV4_NEXT_HOP,
            FieldType.IPV4_SRC_ADDR,
        ):
            if ft.value in fields_idx:
                addr = IPv4Address(self.values[fields_idx.index(ft.value)])
                if addr in network:
                    yield addr

        for ft in (
            FieldType.IPV6_DST_ADDR,
            FieldType.IPV6_NEXT_HOP,
            FieldType.IPV6_SRC_ADDR,
        ):
            if ft.value in fields_idx:
                addr = IPv6Address(self.values[fields_idx.index(ft.value)])
                if addr in network:
                    yield addr
