#!/bin/bash
# Generate self-signed certificates for QUIC interoperability testing
#
# Usage: ./generate.sh
#
# Creates:
#   - priv.key: Private key (ECDSA P-256) - named per quic-interop-runner spec
#   - cert.pem: Self-signed certificate valid for 365 days

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Generating ECDSA P-256 private key..."
openssl ecparam -name prime256v1 -genkey -noout -out priv.key

echo "Generating self-signed certificate..."
openssl req -new -x509 \
    -key priv.key \
    -out cert.pem \
    -days 365 \
    -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

echo "Verifying certificate..."
openssl x509 -in cert.pem -text -noout | grep -A1 "Subject Alternative Name"

echo ""
echo "Certificate files generated:"
echo "  - priv.key (private key)"
echo "  - cert.pem (certificate)"
echo ""
echo "Certificate validity:"
openssl x509 -in cert.pem -noout -dates
