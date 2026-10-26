FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl p7zip-full ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/os-findmy-e
RUN git clone https://github.com/sacca97/os-findmy-e . \
 && git checkout --quiet 374d838 \
 && python -m venv .venv \
 && .venv/bin/pip install --no-cache-dir -r requirements.txt

CMD ["bash"]
