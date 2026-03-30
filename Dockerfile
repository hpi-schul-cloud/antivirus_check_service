FROM ghcr.io/astral-sh/uv:trixie-slim AS builder
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN uv python install 3.14

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev --no-editable

COPY antivirus_service /app/antivirus_service
RUN uv sync --frozen --no-dev --no-editable

FROM gcr.io/distroless/cc-debian13:nonroot

WORKDIR /app

# Copy the standalone Python and virtual environment
COPY --from=builder --chown=root:nonroot /opt/python /opt/python
COPY --from=builder --chown=root:nonroot /app/.venv /app/.venv

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8080

ENTRYPOINT ["/app/.venv/bin/antivirus"]
