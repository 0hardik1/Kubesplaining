# Multi-stage build so `docker build -t kubesplaining:dev .` works from a
# fresh clone (no prebuilt binary needed in context). For tagged releases,
# GoReleaser uses Dockerfile.goreleaser instead, which copies the binary
# it already built and skips the compile step.
#
# Stage 1: compile a static binary with the same ldflags the Makefile uses
# so `kubesplaining version` reports something useful even from a dev image.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Cache module downloads in a separate layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# VERSION/COMMIT/DATE may be passed in via --build-arg; the defaults keep the
# image buildable from a clean source tarball with no .git directory.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/kubesplaining \
      ./cmd/kubesplaining

# Stage 2: distroless static + nonroot. No shell, no package manager,
# runs as UID 65532. The image only contains the binary plus CA certs
# pulled in by the base.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source=https://github.com/0hardik1/kubesplaining
LABEL org.opencontainers.image.title=kubesplaining
LABEL org.opencontainers.image.description="Kubernetes security CLI: RBAC privesc graph, offline snapshot scanning"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=build /out/kubesplaining /usr/local/bin/kubesplaining

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/kubesplaining"]
