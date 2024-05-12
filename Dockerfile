FROM python:3.11-buster as builder

RUN pip install poetry
RUN apt update && apt install -y git python3-setuptools

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN touch README.md

RUN poetry install --no-root && rm -rf $POETRY_CACHE_DIR

# Install the fail2ban library to unpickle data correctly
RUN git clone https://github.com/fail2ban/fail2ban.git
WORKDIR /app/fail2ban
ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"
RUN python3 setup.py install

FROM python:3.11-slim-buster as runtime

WORKDIR /app

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
COPY fail2ban_exporter ./fail2ban_exporter

ENTRYPOINT python3 -m fail2ban_exporter.app