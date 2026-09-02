#!/bin/bash
# gen_certs.sh -- CS6008 Phase 3 PKI setup
#
# Creates a project root CA and a server certificate whose IP SAN matches the
# address clients dial. Run on the Server VM (the CA may live there per §1.2.1).
#
#   ./gen_certs.sh <server-ip>
#   ./gen_certs.sh 192.168.64.2
#
# Produces:
#   ca-key.pem       CA private key         (keep secret; stays on CA host)
#   ca-cert.pem      CA root certificate    (ship to every client)
#   server-key.pem   server private key     (server host ONLY, never shipped)
#   server-cert.pem  CA-signed server cert  (server host)
#   ca.cnf           CA extensions config
#   server.cnf       server CSR + extensions config (with the IP SAN)
#
# All X.509 extensions are set EXPLICITLY rather than relying on OpenSSL
# defaults:
#   CA cert     -> basicConstraints=critical,CA:TRUE
#                  keyUsage=critical,keyCertSign,cRLSign
#   server cert -> basicConstraints=critical,CA:FALSE
#                  keyUsage=critical,digitalSignature,keyEncipherment
#                  extendedKeyUsage=serverAuth
#                  subjectAltName=IP:<server-ip>
#
# Uses only the OpenSSL CLI. No TLS is configured; these are plain X.509 files
# consumed by our own handshake.

set -e

SERVER_IP="${1:-192.168.64.2}"

echo "[*] Generating PKI for server IP: ${SERVER_IP}"

# --- CA extensions config --------------------------------------------------
cat > ca.cnf <<EOF
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage         = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

# --- server CSR + extensions config (carries the IP SAN) -------------------
cat > server.cnf <<EOF
[req]
distinguished_name = dn
prompt             = no

[dn]
C  = IN
O  = CS6008
CN = chat-server

[v3_server]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer

[alt_names]
IP.1 = ${SERVER_IP}
EOF

# --- 1. CA private key -----------------------------------------------------
openssl genrsa -out ca-key.pem 4096

# --- 2. self-signed CA root certificate (10 years), with explicit CA exts --
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 \
    -subj "/C=IN/O=CS6008/CN=CS6008-Root-CA" \
    -extensions v3_ca -config ca.cnf -out ca-cert.pem

# --- 3. server private key -------------------------------------------------
openssl genrsa -out server-key.pem 2048

# --- 4. certificate signing request ----------------------------------------
openssl req -new -key server-key.pem -out server.csr -config server.cnf

# --- 5. CA-signed server certificate, carrying the server extensions -------
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -days 365 -sha256 \
    -extfile server.cnf -extensions v3_server -out server-cert.pem

rm -f server.csr

echo
echo "[*] Verifying the chain:"
openssl verify -CAfile ca-cert.pem server-cert.pem

echo
echo "[*] CA certificate extensions:"
openssl x509 -in ca-cert.pem -noout -text | grep -A1 "Basic Constraints\|Key Usage" | grep -v "^--"

echo
echo "[*] Server certificate extensions:"
openssl x509 -in server-cert.pem -noout -text \
    | grep -A1 "Basic Constraints\|Key Usage\|Extended Key Usage\|Subject Alternative Name" \
    | grep -v "^--"

echo
echo "[*] Done. Ship ca-cert.pem to clients; keep server-key.pem on the server only."
