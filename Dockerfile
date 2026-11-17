# Dead Drop — one static binary with the audited web client compiled into it.
#
#   docker build -t deaddrop .
#
# Most people want install/compose.yaml rather than this file on its own: it
# adds HTTPS and, optionally, a TURN relay. See INSTALL.md.
#
# Both images are pinned by digest, so a build next month uses the same bytes
# as one today; bump them deliberately, in a commit of their own.

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
# The flags the release build uses, so the client it serves is byte for byte
# the one published: `deaddrop version` prints its digest, and anyone can
# compare that with the release's (see INSTALL.md, "Is it the real thing?").
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/deaddrop ./cmd/server/ \
 && /out/deaddrop version \
 && install -d -m 0700 /out/state/data

# No shell, no package manager, nothing but the binary, CA certificates and an
# unprivileged user.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/deaddrop /usr/local/bin/deaddrop
COPY --from=build --chown=65532:65532 /out/state /var/lib/deaddrop
WORKDIR /var/lib/deaddrop
USER 65532:65532
# Loopback only: the web server in front shares this container's network (see
# install/compose.yaml), and the app trusts a visitor's address only from a
# proxy on loopback.
ENV HOST=127.0.0.1 PORT=8100
VOLUME ["/var/lib/deaddrop/data"]
HEALTHCHECK --interval=30s --timeout=12s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/deaddrop", "health"]
ENTRYPOINT ["/usr/local/bin/deaddrop"]
