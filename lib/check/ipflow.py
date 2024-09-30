import ipaddress
import itertools
import logging
from libprobe.asset import Asset
from libprobe.exceptions import IgnoreCheckException
from ..state import subscriptions, subscribe_check, get_host_by_addr


async def check_ipflow(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    try:
        address = check_config['address']
        address = ipaddress.ip_address(address)
    except Exception:
        logging.warning(
            'Check did not run; '
            'address is not provided, invalid or empty')
        raise IgnoreCheckException

    # get current subscription
    subs = subscriptions.get((asset.id, 'ipflow', address))
    result = subs.result if subs else {}

    # re-subscribe
    subscribe_check(asset.id, 'ipflow', address)

    if address.version == 4:
        grouped = itertools.groupby(result, lambda f: (
            str(ipaddress.ip_address(f.values[f.template.index.index(8)])),
            f.values[f.template.index.index(7)],
            str(ipaddress.ip_address(f.values[f.template.index.index(12)])),
            f.values[f.template.index.index(11)],
            str(ipaddress.ip_address(f.values[f.template.index.index(15)]))
            if 15 in f.template.index else None,
            )
        )
    else:
        grouped = itertools.groupby(result, lambda f: (
            str(ipaddress.ip_address(f.values[f.template.index.index(8)])),
            f.values[f.template.index.index(7)],
            str(ipaddress.ip_address(f.values[f.template.index.index(12)])),
            f.values[f.template.index.index(11)],
            str(ipaddress.ip_address(f.values[f.template.index.index(15)]))
            if 15 in f.template.index else None,
            )
        )

    items = []
    for (src, src_port, dst, dst_port, next_hop), g in grouped:
        item = {
            'name': f'{src}|{src_port}|{dst}|{dst_port}|{next_hop or ""}',
            'src_host': get_host_by_addr(src),
            'src_addr': src,
            'src_port': src_port,
            'dst_host': get_host_by_addr(dst),
            'dst_addr': dst,
            'dst_port': dst_port,
            'next_hop': next_hop,
            'next_hop_host': next_hop and get_host_by_addr(next_hop),
            'in_pkts': 0,
            'in_bytes': 0,
        }
        items.append(item)

        for f in g:
            item['in_bytes'] += f.values[f.template.index.index(1)]
            item['in_pkts'] += f.values[f.template.index.index(2)]

        # TODO
        # some of these can vary per flow
        # find out if we should make list metrics or apply other aggregations
        item['protocol'] = f.values[f.template.index.index(4)]
        item['tos'] = f.values[f.template.index.index(5)] \
            if 5 in f.template.index else None
        item['tcp_flags'] = f.values[f.template.index.index(6)] \
            if 6 in f.template.index else None
        item['input_snmp'] = f.values[f.template.index.index(10)] \
            if 10 in f.template.index else None
        item['output_snmp'] = f.values[f.template.index.index(14)] \
            if 14 in f.template.index else None
        item['last_switched'] = f.values[f.template.index.index(21)] \
            if 21 in f.template.index else None
        item['first_switched'] = f.values[f.template.index.index(22)] \
            if 22 in f.template.index else None

    state_data = {
        'ipflow': items,
    }
    return state_data
