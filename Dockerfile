# syntax=docker/dockerfile:1
# SafeStream-Redactor — streaming PII & credential redaction.
#
# Build:  docker build -t safestream-redactor .
# Run:    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/data \
#             safestream-redactor redact /data/input.txt -o /data/output.txt
#
# --user makes the container read and write as you. Without it the image runs as
# its own unprivileged uid 10001, which cannot write into a bind-mounted
# directory owned by your host user (Permission denied). Streaming needs no
# mount at all:
#         docker run --rm -i safestream-redactor redact - -o - < in.txt > out.txt
#
# The image installs only the constant-memory core (no third-party runtime
# deps), so it stays small and runs fully offline.

# One base for both stages (the venv's interpreter symlinks must resolve in the
# runtime stage). Pinned by multi-arch index digest for reproducible builds;
# Dependabot (docker ecosystem) proposes digest bumps.
ARG PYTHON_IMAGE=python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

FROM ${PYTHON_IMAGE} AS build
# Reproducible output: with SOURCE_DATE_EPOCH set, hatchling stamps the wheel and
# py_compile writes hash-based .pyc (no source mtimes). Pass the same value as a
# build arg with `--output ...,rewrite-timestamp=true` for bit-identical layers.
ARG SOURCE_DATE_EPOCH=0
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /src
# Hash-locked build backend in its own venv, so the wheel is built by exactly
# the same hatchling every time and none of it leaks into the runtime image.
COPY docker/build-requirements.txt /tmp/
RUN python -m venv /opt/build \
 && /opt/build/bin/pip install --require-hashes --no-deps -r /tmp/build-requirements.txt
# Sources last: editing code does not invalidate the dependency layer above.
COPY pyproject.toml LICENSE ./
COPY src ./src
RUN /opt/build/bin/pip wheel --no-build-isolation --no-deps -w /dist . \
 && python -m venv --without-pip /opt/venv \
 && /opt/build/bin/pip --python /opt/venv/bin/python install /dist/*.whl

FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="safestream-redactor" \
      org.opencontainers.image.description="Streaming PII & credential redaction with constant memory usage" \
      org.opencontainers.image.source="https://github.com/MounishSenisetty/SafeStream-Redactor" \
      org.opencontainers.image.licenses="MIT"

# The venv arrives fully installed with bytecode precompiled: pip never runs in
# this stage, so no build tools, caches or runtime .pyc churn land in a layer.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Run as an unprivileged user; the tool never needs root. A numeric USER lets
# orchestrators verify non-root statically (Kubernetes runAsNonRoot).
RUN groupadd --gid 10001 safestream \
 && useradd --create-home --uid 10001 --gid 10001 safestream
COPY --from=build /opt/venv /opt/venv

USER 10001:10001
WORKDIR /data

ENTRYPOINT ["safestream"]
CMD ["--help"]
