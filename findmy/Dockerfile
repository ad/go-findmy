ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-debian:bookworm

# The release workflow builds with findmy/ as the context and --build-context src=. (the checkout
# of the tag). Without that override the src stage clones the tag, which is what Supervisor would
# do if config.yaml had no image: line.
FROM golang:1.27-bookworm AS clone
ARG BUILD_VERSION
RUN git clone --depth 1 --branch "v${BUILD_VERSION}" https://github.com/ad/go-findmy /src

FROM scratch AS src
COPY --from=clone /src /

FROM golang:1.27-bookworm AS build
COPY --from=src / /build
WORKDIR /build
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /go-findmy ./cmd/go-findmy

# git and the venv tooling are only needed to fetch and install os-findmy-e; they stay in this stage.
FROM $BUILD_FROM AS osfe
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/os-findmy-e
RUN git clone https://github.com/sacca97/os-findmy-e . \
 && git checkout --quiet 374d838 \
 && rm -rf .git \
 && python3 -m venv .venv \
 && .venv/bin/pip install --no-cache-dir -r requirements.txt \
 && .venv/bin/pip uninstall -y pip setuptools

FROM $BUILD_FROM
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl p7zip-full ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=osfe /opt/os-findmy-e /opt/os-findmy-e
COPY --from=src /sidecar/anisette_sidecar.py /opt/anisette_sidecar.py
COPY --from=build /go-findmy /usr/local/bin/go-findmy
COPY run.sh /run.sh
CMD ["/run.sh"]
