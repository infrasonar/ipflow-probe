import asyncio
from libprobe.probe import Probe
from lib.check.ipflow import check_ipflow
from lib.server import start_server
from lib.state import cleanup_subscriptions_loop
from lib.version import __version__ as version


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_server())
    asyncio.ensure_future(cleanup_subscriptions_loop())

    checks = {
        'ipflow': check_ipflow,
    }

    probe = Probe("ipflow", version, checks)

    probe.start()
