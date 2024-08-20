import struct
from .field import Field
from .flow import Flow, flowset_templates
from .template import DataTemplate


def on_flowset_template(
    line: bytes,
    source: str,
    source_id: int,
    source_uptime: int,
):
    pos = 0
    while pos < len(line):
        template_id, field_count = struct.unpack('>HH', line[pos:pos+4])
        # rfc 3954 5.1
        # NetFlow Collectors SHOULD use the combination of the source IP
        # address and the Source ID field to separate different export
        # streams originating from the same Exporter.
        key = source, source_id, template_id
        template = flowset_templates.get(key)
        if template and template.source_uptime < source_uptime:
            pos += 4 + field_count * 4
            continue

        fields = [
            Field(*struct.unpack('>HH', line[i:i+4]))
            for i in range(pos + 4, pos + 4 + field_count * 4, 4)
        ]

        pos += 4 + field_count * 4
        flowset_templates[key] = DataTemplate(
            '>' + ''.join(f._fmt for f in fields),
            sum(f.length for f in fields),
            fields,
            [f.id for f in fields],
            source_uptime,
        )


def on_flowset(
    line: bytes,
    flowset_id: int,
    source: str,
    source_id: int,
):
    key = source, source_id, flowset_id
    template = flowset_templates.get(key)
    if template:
        fmt = template._fmt
        pad = len(line) % template.length
        for values in struct.iter_unpack(fmt, line[:-pad] if pad else line):
            yield Flow(template, values)
