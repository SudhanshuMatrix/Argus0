FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build GOOS="$TARGETOS" GOARCH="$TARGETARCH"

FROM scratch
WORKDIR /app
COPY --from=builder /src/bin/argus /app/argus
COPY configs/default.yaml /app/configs/default.yaml
EXPOSE 9090
ENTRYPOINT ["/app/argus"]
