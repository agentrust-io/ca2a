# Base image pinned by its multi-arch index digest, so a re-pushed tag cannot
# change what is built. Refresh the digest and the tag together.
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements/build.txt ./requirements/build.txt
# The build backend comes from a hash-pinned lock, and the wheel is built
# without build isolation so pip does not fetch an unpinned hatchling of its own.
RUN python -m pip install --require-hashes -r requirements/build.txt
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 ca2a \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/ca2a ca2a \
    && install -d -o ca2a -g ca2a /var/lib/ca2a /etc/ca2a

# Third-party runtime dependencies from the hash-pinned lock, then the locally
# built wheel with --no-deps, so nothing in the image is resolved unpinned.
COPY requirements/runtime.txt /tmp/runtime.txt
COPY --from=builder /wheels /wheels
RUN python -m pip install --require-hashes -r /tmp/runtime.txt \
    && python -m pip install --no-deps /wheels/ca2a_runtime-*.whl \
    && rm -rf /wheels /tmp/runtime.txt

USER 10001:10001
WORKDIR /var/lib/ca2a
EXPOSE 8443

ENTRYPOINT ["ca2a"]
CMD ["--help"]
