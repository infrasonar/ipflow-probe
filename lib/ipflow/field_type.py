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

    # NAT
    # postNATSourceIPv4Address = 225
    # postNATDestinationIPv4Address = 226
    # postNAPTSourceTransportPort = 227
    # postNAPTDestinationTransportPort = 228
    # natOriginatingAddressRealm = 229
    # natEvent = 230


FIELD_TYPE_FMT: dict[tuple[int, int], str] = {
    (1, 4): 'L',
    (1, 8): 'Q',  # also uint64
    (2, 4): 'L',
    (2, 8): 'Q',  # also uint64
    (3, 4): 'L',
    (3, 8): 'Q',  # also uint64
    (4, 1): 'B',
    (5, 1): 'B',
    (6, 1): 'B',
    (7, 2): 'H',
    (8, 4): '4s',
    (9, 1): 'B',
    (10, 2): 'H',
    (11, 2): 'H',
    (12, 4): '4s',
    (13, 1): 'B',
    (14, 2): 'H',
    (15, 4): '4s',
    (21, 4): 'L',
    (21, 8): 'Q',  # also uint64
    (22, 4): 'L',
    (22, 8): 'Q',  # also uint64
    (27, 16): '16s',
    (28, 16): '16s',
    (29, 1): 'B',
    (30, 1): 'B',
    (62, 16): '16s',

    # NAT
    # (225, 4): '4s',
    # (226, 4): '4s',
    # (227, 2): 'H',
    # (228, 2): 'H',
    # (229, 1): 'B',
    # (230, 1): 'B',
}

FIELD_TYPE_FUNC = {
    8: lambda a: str(ipaddress.IPv4Address(a)),  # IPV4_SRC_ADDR
    12: lambda a: str(ipaddress.IPv4Address(a)),  # IPV4_DST_ADDR
    15: lambda a: str(ipaddress.IPv4Address(a)),  # IPV4_NEXT_HOP
    27: lambda a: str(ipaddress.IPv6Address(a)),  # IPV6_SRC_ADDR
    28: lambda a: str(ipaddress.IPv6Address(a)),  # IPV6_DST_ADDR
    62: lambda a: str(ipaddress.IPv6Address(a)),  # IPV6_NEXT_HOP

    # NAT
    # 225: lambda a: str(ipaddress.IPv4Address(a)),
    # 226: lambda a: str(ipaddress.IPv4Address(a)),
}
