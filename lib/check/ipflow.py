import ipaddress
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
    subs = subscriptions.get((asset.id, 'ipflow'))
    result = subs.result if subs else {}

    # re-subscribe
    subscribe_check(asset.id, 'ipflow', address)

    state_data = {
        'ipflow': [{
            'name': f'{flow.idx}',
            'src_host': get_host_by_addr(flow.ipv4_src_addr),
            'dst_host': get_host_by_addr(flow.ipv4_dst_addr),
            **flow.serialize(),
        } for flow in result],
    }
    return state_data
