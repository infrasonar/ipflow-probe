import time
from ipaddress import IPv4Address, IPv6Address
from typing import NamedTuple, Union
from .ipflow.flow import Flow


class Subscription(NamedTuple):
    address: Union[IPv4Address, IPv6Address]
    result: list[Flow]
    timestamp: int

    @classmethod
    def make(cls, address: Union[IPv4Address, IPv6Address]):
        self = cls(
            address=address,
            result=[],
            timestamp=int(time.time()),
        )
        return self

    def on_flow(self, flow: Flow):
        # compare the raw address bytes against all parsed fields regardless of
        # field type
        if self.address.packed in flow.values:
            self.result.append(flow)
