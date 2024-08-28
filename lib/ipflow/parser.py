import logging
import struct
from .flowset import on_flowset, on_flowset_template


HEADER_FMT = '>HHLLLL'
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def on_packet(line: bytes, source: str):
    (
        version,
        count,
        sysuptime,
        unix_secs,
        sequence_number,
        source_id,
    ) = struct.unpack_from(HEADER_FMT, line)

    # we don't use header.count because it includes the Options Template
    # FlowSets (FlowSet ID 1), which we ignore
    pos = HEADER_SIZE
    while pos + 4 < len(line):
        flowset_id, length = struct.unpack_from('>HH', line, pos)

        # prevent endless loop
        if length == 0:
            logging.error('failed to parse packet')
            break

        if flowset_id == 0:
            try:
                on_flowset_template(line, pos + 4, pos + length, source,
                                    source_id, sysuptime)
            except Exception:
                logging.error('failed to parse FlowSet template')
                break
        elif flowset_id > 255:
            try:
                for flow in on_flowset(line, pos + 4, pos + length, flowset_id,
                                       source, source_id):
                    yield flow
            except Exception:
                logging.warning('failed to parse FlowSet')
                break
        pos += length
