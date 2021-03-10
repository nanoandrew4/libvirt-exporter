# Stage 1: Build libvirt exporter
FROM golang:1.14.4

COPY libvirt_exporter.go .
COPY go.mod .

# Build and strip exporter
RUN go get -d ./... && \
    go build && \
    strip libvirt_exporter

# Entrypoint for starting exporter
ENTRYPOINT [ "./libvirt_exporter" ]
