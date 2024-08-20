import struct
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Dict, Iterator, Tuple, Union
from .field_type import FIELD_TYPE_FUNC
from .field_type import FieldType
from .template import DataTemplate


V5_TEMPLATE_KEY = None, None, None
V5_TEMPLATE_FMT = '>4s4s4sHHLLLLHH2sBBB3s4s'
V5_TEMPLATE_SIZE = struct.calcsize(V5_TEMPLATE_FMT)

flowset_templates: Dict[Tuple[str, int, int], DataTemplate] = {
    V5_TEMPLATE_KEY: DataTemplate(
        V5_TEMPLATE_FMT,
        V5_TEMPLATE_SIZE,
        [],
        [
            FieldType.IPV4_SRC_ADDR,
            FieldType.IPV4_DST_ADDR,
            FieldType.IPV4_NEXT_HOP,
            FieldType.INPUT_SNMP,
            FieldType.OUTPUT_SNMP,
            FieldType.IN_PKTS,
            FieldType.IN_BYTES,
            FieldType.FIRST_SWITCHED,
            FieldType.LAST_SWITCHED,
            FieldType.L4_SRC_PORT,
            FieldType.L4_DST_PORT,
            None,  # 1 byte padding
            FieldType.PROTOCOL,
            FieldType.TOS,
            FieldType.TCP_FLAGS,
            None,  # 3 byte padding
            None,  # reserved
        ],
        0,  # uptime not used for v5 packets
    )
}


class Flow:
    __slots__ = (
        'template',
        'values',
    )

    def __init__(self, template: DataTemplate, values: Tuple[bytes]):
        self.template = template
        self.values = values

    def serialize(self) -> dict:
        fields = self.template.fields
        return {
            f.name: FIELD_TYPE_FUNC.get(f.id, lambda val: val)(val)
            for f, val in zip(fields, self.values)
        }

    def test_address(
        self,
        address: Union[IPv4Address, IPv6Address]
    ) -> Iterator[Union[IPv4Address, IPv6Address]]:
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

    def test_network(
        self,
        network: Union[IPv4Network, IPv6Network]
    ) -> Iterator[Union[IPv4Network, IPv6Network]]:
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
