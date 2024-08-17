import struct
from .field import Field
from .flow import Flow, flowset_templates


def on_flowset_template(line: bytes):
    pos = 0
    while pos < len(line):
        template_id, field_count = struct.unpack('>HH', line[pos:pos+4])
        fields = [
            Field(*struct.unpack('>HH', line[i:i+4]))
            for i in range(pos + 4, pos + 4 + field_count * 4, 4)
        ]

        pos += 4 + field_count * 4
        flowset_templates[template_id] = (
            '>' + ''.join(f._fmt for f in fields),
            sum(f.length for f in fields),
            fields,
            [f.id for f in fields],
        )


def on_flowset(line: bytes, flowset_id: int):
    if flowset_id in flowset_templates:
        fmt, length, _, _ = flowset_templates[flowset_id]
        for i in range(0, len(line) - 4, length):
            values = struct.unpack(fmt, line[i:i+length])
            yield Flow(flowset_id, values)
