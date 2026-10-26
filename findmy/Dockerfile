ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-debian:bookworm

# Supervisor builds with findmy/ as the context, so the sources come from the release tag.
# Local build from a checkout: docker build --build-context src=. findmy
FROM golang:1.27-bookworm AS clone
ARG BUILD_VERSION
RUN git clone --depth 1 --branch "v${BUILD_VERSION}" https://github.com/ad/go-findmy /src

FROM scratch AS src
COPY --from=clone /src /

FROM golang:1.27-bookworm AS build
COPY --from=src / /build
WORKDIR /build
RUN CGO_ENABLED=0 go build -trimpath -o /go-findmy ./cmd/go-findmy

FROM $BUILD_FROM
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl p7zip-full ca-certificates python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/os-findmy-e
RUN git clone https://github.com/sacca97/os-findmy-e . \
 && git checkout --quiet 374d838 \
 && python3 -m venv .venv \
 && .venv/bin/pip install --no-cache-dir -r requirements.txt

COPY --from=src /sidecar/anisette_sidecar.py /opt/anisette_sidecar.py
COPY --from=build /go-findmy /usr/local/bin/go-findmy
COPY run.sh /run.sh
CMD ["/run.sh"]
