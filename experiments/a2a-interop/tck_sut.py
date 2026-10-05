"""Run the upstream generated TCK SUT, optionally adding cA2A discovery and parsing.

This is a baseline-protocol probe, not a protected-operation service. cA2A enforcement
is exercised separately by the repository's real SDK HTTP loopback tests.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
from pathlib import Path

from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport.a2a_sdk import merge_agent_card, parse_sdk_message


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tck", type=Path, required=True)
    parser.add_argument("--ca2a", action="store_true")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location(
        "upstream_tck_sut", args.tck / "sut/a2a-python/sut_agent.py"
    )
    assert spec and spec.loader
    sut = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sut)
    if args.ca2a:
        node = PeerNode(LocalPolicy.of(set()))
        original_card = sut.AgentCard
        sut.AgentCard = lambda **kwargs: merge_agent_card(original_card(**kwargs), node)
        original_executor = sut.TckAgentExecutor

        class ProfileExecutor(original_executor):
            async def execute(self, context, event_queue):
                if parse_sdk_message(context.message) is not None:
                    raise ValueError("This conformance probe does not serve protected operations")
                await super().execute(context, event_queue)

        sut.TckAgentExecutor = ProfileExecutor
    asyncio.run(sut.main())


if __name__ == "__main__":
    main()
