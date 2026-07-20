"""ca2a-verify - verify cA2A delegation chains and the delegation DAG offline.

Verification does not require trusting any operator: a chain is checked against
the issuers' public keys and the attenuation invariants alone.
"""

from ca2a_verify.dag import (
    TraceDagResult,
    cross_check_trace_dag,
    verify_trace_dag,
)
from ca2a_verify.verify import (
    ChainResult,
    VerificationError,
    verify_chain_file,
    verify_delegation_chain,
)

__version__ = "0.1.0"
__all__ = [
    "ChainResult",
    "TraceDagResult",
    "VerificationError",
    "cross_check_trace_dag",
    "verify_chain_file",
    "verify_delegation_chain",
    "verify_trace_dag",
]
