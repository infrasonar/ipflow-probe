import time
from ipaddress import IPv4Address, IPv6Address
from typing import List, NamedTuple, Union
from .ipflow.flow import Flow


class Subscription(NamedTuple):
    address: Union[IPv4Address, IPv4Address]
    result: List[Flow]
    timestamp: int

    @classmethod
    def make(cls, address: Union[IPv4Address, IPv6Address]):
        self = cls(
            address=address,
            result={},
            timestamp=int(time.time()),
        )
        return self

    def on_flow(self, flow: Flow):
        if flow.test_address(self.address):
            self.append(flow)
