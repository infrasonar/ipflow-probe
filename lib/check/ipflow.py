import ipaddress
import itertools
import logging
from libprobe.asset import Asset
from libprobe.check import Check
from libprobe.exceptions import IgnoreCheckException
from typing import Any
from ..ipflow.flow import Flow
from ..state import subscriptions, subscribe_check, get_host_by_addr


def on_result(flows: list[Flow]) -> list[dict[str, Any]]:

    grouped = itertools.groupby(flows, lambda f: (
        f.values[f.template.index.index(8)],
        f.values[f.template.index.index(7)],
        f.values[f.template.index.index(12)],
        f.values[f.template.index.index(11)],
        f.values[f.template.index.index(15)]
        if 15 in f.template.index else None,
    ))

    items = []
    for (src, src_port, dst, dst_port, next_hop), g in grouped:
        src = str(ipaddress.ip_address(src))
        dst = str(ipaddress.ip_address(dst))
        next_hop = str(ipaddress.ip_address(next_hop)) if next_hop else None
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

        for i, f in enumerate(g):
            item['in_bytes'] += f.values[f.template.index.index(1)]
            item['in_pkts'] += f.values[f.template.index.index(2)]

            if i == 0:
                # TODO
                # some of these can vary per flow
                # find out if we should make list metrics or apply other
                # aggregations
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

    return items


class CheckIpflow(Check):
    key = 'ipflow'
    unchanged_eol = 14400

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:

        try:
            address = config['address']
            address = ipaddress.ip_address(address)
        except Exception:
            logging.warning(
                'Check did not run; '
                'address is not provided, invalid or empty')
            raise IgnoreCheckException

        # get current subscription
        subs = subscriptions.get((asset.id, 'ipflow', address))
        result = subs.result if subs else []

        # re-subscribe
        subscribe_check(asset.id, 'ipflow', address)

        # parse flows
        items = on_result(result)

        state_data = {
            'ipflow': items,
        }
        return state_data
