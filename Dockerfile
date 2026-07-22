# SafeStream-Redactor — streaming PII & credential redaction.
#
# Build:  docker build -t safestream-redactor .
# Run:    docker run --rm -v "$PWD":/data safestream-redactor \
#             redact /data/input.txt -o /data/output.txt
#
# The image installs only the constant-memory core (no third-party runtime
# deps), so it stays small and runs fully offline.
FROM python:3.12-slim AS build

WORKDIR /src
# Copy only what the build backend (hatchling) needs to produce the wheel.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim AS runtime

# Run as an unprivileged user; the tool never needs root.
RUN useradd --create-home --uid 10001 safestream
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

USER safestream
WORKDIR /data

ENTRYPOINT ["safestream"]
CMD ["--help"]
