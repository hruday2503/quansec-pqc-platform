# syntax=docker/dockerfile:1.7
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 openssh-client openssh-server systemd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin quanseq

WORKDIR /app
COPY quanseq/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip && python -m pip install -r /tmp/requirements.txt
COPY quanseq/ /app/

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "services.api:app", "--host", "0.0.0.0", "--port", "8000"]
