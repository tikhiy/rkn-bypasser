FROM alpine:3.9 AS builder

ARG TOR_VERSION=0.4.0.4-rc

RUN apk add --no-cache make automake autoconf gcc libtool curl libevent-dev \
musl musl-dev libgcc openssl openssl-dev openssh zlib-dev

RUN curl https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz | tar xz

WORKDIR tor-${TOR_VERSION}

RUN ./configure && make && make install

RUN echo "Log notice stdout" >> /etc/torrc && \
echo "SocksPort 0.0.0.0:9150" >> /etc/torrc && \
echo 'DataDirectory /var/lib/tor' >> /etc/torrc



FROM alpine:3.9

RUN apk add --no-cache libevent musl openssl openssh

WORKDIR /

COPY --from=builder /usr/local/bin/tor /
COPY --from=builder /etc/torrc /torrc

ENTRYPOINT ["/tor", "-f", "/torrc"]
