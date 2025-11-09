FROM python:3.12-slim-bookworm AS builder
ENV DEBIAN_FRONTEND=noninteractive
# install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
# create a place to build stuff as nobody user
RUN mkdir -p /home/nobody/build && chown -R nobody:nogroup /home/nobody
USER nobody
ENV HOME=/home/nobody
ENV UV_CACHE_DIR=/home/nobody/.cache
ENV PIP_DISABLE_PIP_VERSION_CHECK=on
WORKDIR $HOME

COPY main.py pyproject.toml .python-version uv.lock .
RUN uv sync
ENTRYPOINT ["uv", "run", "main.py"]
