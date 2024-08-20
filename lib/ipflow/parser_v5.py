import logging
import struct
from .flowset import on_flowset
from .flow import V5_TEMPLATE_KEY, V5_TEMPLATE_SIZE


HEADER_FMT = '>HHLLLLBBH'
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def on_packet_v5(line: bytes):
    (
        version,
        count,
        sysuptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval
    ) = struct.unpack(HEADER_FMT, line[:HEADER_SIZE])

    flowset_size = V5_TEMPLATE_SIZE
    pos = HEADER_SIZE
    for _ in range(count):
        flowset = line[pos:pos+flowset_size]
        pos += flowset_size

        try:
            for flow in on_flowset(flowset, *V5_TEMPLATE_KEY):
                yield flow
        except Exception:
            logging.warning('failed to parse FlowSet')
            break
