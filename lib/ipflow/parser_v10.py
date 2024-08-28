import logging
import struct
from .flowset import on_flowset, on_flowset_template


HEADER_FMT = '>HHLLL'
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def on_packet_v10(line: bytes, source: str):
    (
        version,
        message_length,
        export_time,
        sequence_number,
        observation_domain_id,
    ) = struct.unpack_from(HEADER_FMT, line)

    pos = HEADER_SIZE
    while pos + 4 < len(line) and pos < message_length:
        flowset_id, length = struct.unpack_from('>HH', line, pos)

        # prevent endless loop
        if length == 0:
            logging.error('failed to parse packet')
            break

        if flowset_id == 2:
            try:
                on_flowset_template(line, pos + 4, pos + length, source,
                                    observation_domain_id, export_time)
            except Exception:
                logging.error('failed to parse FlowSet template')
                break
        elif flowset_id > 255:
            try:
                for flow in on_flowset(line, pos + 4, pos + length, flowset_id,
                                       source, observation_domain_id):
                    yield flow
            except Exception:
                logging.warning('failed to parse FlowSet')
                break
        pos += length
