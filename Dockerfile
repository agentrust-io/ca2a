FROM python:3.11.15-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.11.15-slim-bookworm AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 ca2a \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/ca2a ca2a \
    && install -d -o ca2a -g ca2a /var/lib/ca2a /etc/ca2a

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels ca2a-runtime \
    && rm -rf /wheels

USER 10001:10001
WORKDIR /var/lib/ca2a
EXPOSE 8443

ENTRYPOINT ["ca2a"]
CMD ["--help"]
