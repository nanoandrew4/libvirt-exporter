#!/bin/sh

docker run -i -v `pwd`:/libvirt-exporter golang:1.14.4 /bin/sh << 'EOF'
set -ex

# Build the libvirt_exporter.
cd /libvirt-exporter
go build
strip libvirt_exporter
EOF
