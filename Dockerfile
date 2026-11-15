FROM --platform=$BUILDPLATFORM golang:1.27.1 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY volcengine.go environment.go ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/volcengine-dns01 ./cmd/volcengine-dns01

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/volcengine-dns01 /volcengine-dns01
USER 65532:65532
ENTRYPOINT ["/volcengine-dns01"]
