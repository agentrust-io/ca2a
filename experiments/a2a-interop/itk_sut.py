"""Run the pinned official Python ITK peer with optional cA2A discovery.

Windows lacks loop.add_signal_handler; the owning controller terminates this
local test process. No upstream application or SDK sources are changed.
"""

import argparse
import asyncio
import importlib.util
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--sdk", type=Path, required=True)
parser.add_argument("--itk", type=Path, required=True)
parser.add_argument("--ca2a", action="store_true")
args = parser.parse_args()
sys.path[:0] = [str(args.sdk / "itk"), str(args.itk)]
spec = importlib.util.spec_from_file_location("official_itk_peer", args.sdk / "itk/main.py")
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
if args.ca2a:
    from ca2a_runtime.node import PeerNode
    from ca2a_runtime.policy import LocalPolicy
    from ca2a_runtime.transport.a2a_sdk import merge_agent_card, parse_sdk_message

    node = PeerNode(LocalPolicy.of(set()))
    original_card = peer.AgentCard
    peer.AgentCard = lambda **kwargs: merge_agent_card(original_card(**kwargs), node)

    class ExtendedExecutor(peer.V10AgentExecutor):
        async def execute(self, context, event_queue):
            if parse_sdk_message(context.message) is not None:
                raise ValueError("This traversal probe does not serve protected operations")
            await super().execute(context, event_queue)

    peer.V10AgentExecutor = ExtendedExecutor


async def main():
    if sys.platform == "win32":
        asyncio.get_running_loop().add_signal_handler = lambda *a, **kw: None
    await peer.main_async(19001, 19002)


asyncio.run(main())
