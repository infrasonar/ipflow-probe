from enum import Enum
import ipaddress


class FieldType(Enum):
    IN_BYTES = 1
    IN_PKTS = 2
    FLOWS = 3
    PROTOCOL = 4
    TOS = 5
    TCP_FLAGS = 6
    L4_SRC_PORT = 7
    IPV4_SRC_ADDR = 8
    SRC_MASK = 9
    INPUT_SNMP = 10
    L4_DST_PORT = 11
    IPV4_DST_ADDR = 12
    DST_MASK = 13
    OUTPUT_SNMP = 14
    IPV4_NEXT_HOP = 15
    LAST_SWITCHED = 21
    FIRST_SWITCHED = 22
    IPV6_SRC_ADDR = 27
    IPV6_DST_ADDR = 28
    IPV6_SRC_MASK = 29
    IPV6_DST_MASK = 30
    IPV6_NEXT_HOP = 62


FIELD_TYPE_FMT = {
    1: 'L',
    2: 'L',
    4: 'B',
    5: 'B',
    6: 'B',
    7: 'H',
    10: 'H',
    11: 'H',
    14: 'H',
    21: 'L',
    22: 'L',
    # 27: 'LLLL',
    # 28: 'LLLL',
    # 62: 'LLLL',
    # 63: 'LLLL',
    227: 'H',  # postNAPTSourceTransportPort
    228: 'H',  # postNAPTDestinationTransportPort
    230: 'B',  # natEvent
    323: 'Q',
}

FIELD_TYPE_FUNC = {
    8: lambda a: str(ipaddress.IPv4Address(a)),  # IPV4_SRC_ADDR
    12: lambda a: str(ipaddress.IPv4Address(a)),  # IPV4_DST_ADDR
    15: lambda a: str(ipaddress.IPv4Address(a)),  # IPV4_NEXT_HOP
    27: lambda a: str(ipaddress.IPv6Address(a)),  # IPV6_SRC_ADDR
    28: lambda a: str(ipaddress.IPv6Address(a)),  # IPV6_DST_ADDR
    62: lambda a: str(ipaddress.IPv6Address(a)),  # IPV6_NEXT_HOP
    63: lambda a: str(ipaddress.IPv6Address(a)),  # BGP_IPV6_NEXT_HOP

    225: lambda a: str(ipaddress.IPv4Address(a)),
    226: lambda a: str(ipaddress.IPv4Address(a)),
}
