# ngtcp2 QUIC server for interoperability testing
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libev-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build quictls (OpenSSL fork with QUIC support)
RUN git clone --depth 1 -b openssl-3.1.4+quic https://github.com/quictls/openssl.git && \
    cd openssl && \
    ./config --prefix=/opt/quictls --openssldir=/opt/quictls/ssl && \
    make -j$(nproc) && \
    make install_sw && \
    # Verify QUIC support (lib for ARM64, lib64 for x86_64)
    nm /opt/quictls/lib/libssl.so | grep -q SSL_provide_quic_data && echo "QUIC support confirmed"

# Build nghttp3
RUN git clone --depth 1 -b v1.1.0 https://github.com/ngtcp2/nghttp3.git && \
    cd nghttp3 && \
    autoreconf -fi && \
    ./configure --prefix=/usr/local --enable-lib-only && \
    make -j$(nproc) && \
    make install

# Build ngtcp2 with quictls - use explicit paths
RUN git clone --depth 1 -b v1.2.0 https://github.com/ngtcp2/ngtcp2.git && \
    cd ngtcp2 && \
    autoreconf -fi && \
    PKG_CONFIG_PATH=/opt/quictls/lib/pkgconfig \
    OPENSSL_CFLAGS="-I/opt/quictls/include" \
    OPENSSL_LIBS="-L/opt/quictls/lib -lssl -lcrypto" \
    LDFLAGS="-L/opt/quictls/lib -Wl,-rpath,/opt/quictls/lib" \
    ./configure --prefix=/usr/local --with-openssl && \
    make -j$(nproc) && \
    make install

# Copy server binary to /usr/local/bin
RUN cp /build/ngtcp2/examples/qtlsserver /usr/local/bin/qtlsserver && \
    cp /build/ngtcp2/examples/qtlsclient /usr/local/bin/qtlsclient

# Update library paths
RUN echo "/opt/quictls/lib" > /etc/ld.so.conf.d/quictls.conf && \
    echo "/usr/local/lib" >> /etc/ld.so.conf.d/quictls.conf && \
    ldconfig

# Create directories
RUN mkdir -p /certs /www /logs

WORKDIR /

# Expose QUIC port
EXPOSE 443/udp

# Set library path at runtime
ENV LD_LIBRARY_PATH=/opt/quictls/lib:/usr/local/lib

# Default command - run server (qtlsserver uses: addr port key cert)
CMD ["/usr/local/bin/qtlsserver", "*", "443", "/certs/server.key", "/certs/server.crt"]
