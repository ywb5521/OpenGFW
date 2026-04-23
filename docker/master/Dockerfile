FROM golang:1.26.2-bookworm AS build

WORKDIR /src
COPY . .
RUN go build -trimpath -o /out/opengfw-master ./cmd/opengfw-master

FROM golang:1.26.2-bookworm

WORKDIR /opt/opengfw
COPY . /opt/opengfw
COPY --from=build /out/opengfw-master /usr/local/bin/opengfw-master
COPY docker/master/entrypoint.sh /usr/local/bin/opengfw-master-entrypoint

RUN chmod +x /usr/local/bin/opengfw-master-entrypoint \
    && mkdir -p /var/lib/opengfw-master

EXPOSE 9527

WORKDIR /var/lib/opengfw-master
ENTRYPOINT ["/usr/local/bin/opengfw-master-entrypoint"]
