import struct
from .field import Field
from .flow import Flow, flowset_templates
from .template import DataTemplate


def on_flowset_template(
    line: bytes,
    pos: int,
    pos_end: int,
    source: str,
    source_id: int,
    source_uptime: int,
):
    while pos < pos_end:
        template_id, field_count = struct.unpack_from('>HH', line, pos)
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
            Field(*struct.unpack_from('>HH', line, i))
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
    pos: int,
    pos_end: int,
    flowset_id: int,
    source: str,
    source_id: int,
):
    key = source, source_id, flowset_id
    template = flowset_templates.get(key)
    if template:
        # assume 3 padding
        for i in range(pos, pos_end - 3, template.length):
            yield Flow(template, template._fmt.unpack_from(line, i))
