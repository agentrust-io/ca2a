#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# Installed rather than put on the path so the targets exercise the same import
# surface a consumer gets. Third-party dependencies come from the same
# hash-pinned locks the container image uses, and the package goes in with
# --no-deps and without build isolation, so nothing here resolves unpinned.

cd "$SRC/ca2a"
pip3 install --no-cache-dir --require-hashes -r requirements/build.txt
pip3 install --no-cache-dir --require-hashes -r requirements/runtime.txt
pip3 install --no-cache-dir --no-deps --no-build-isolation .

# compile_python_fuzzer bundles each target with PyInstaller, which follows
# static imports only and bundles code, not package data.
PYI_ARGS=(
  # The cryptography and pydantic stacks reach email.mime lazily; without this
  # the bundled target dies with ModuleNotFoundError, which libFuzzer reports
  # as a crash in the target.
  --collect-submodules=email
  # ca2a_verify.dag validates records against the TRACE JSON schema, which
  # agentrust_trace loads from inside its package at import time.
  --collect-data=agentrust_trace
  --collect-data=agent_manifest
)

for target in "$SRC"/ca2a/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done
