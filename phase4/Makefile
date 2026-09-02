# CS6008 Phase 3 -- Makefile
#
#   make            build server, client, dh_test, tamper_proxy,
#                   mitm_proxy (Phase 2), mitm_proxy_p3 (Phase 3 attacks)
#   make certs      generate the CA + server certificate (IP defaults to
#                   127.0.0.1; override with:  make certs IP=192.168.64.2)
#   make check      build, run the DH test, and prove no prohibited API is used
#   make clean

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pthread
LDLIBS   := -lcrypto -pthread

# certs.cpp is part of the client and server from Phase 3 onward.
COMMON   := dh.cpp crypto.cpp net.cpp certs.cpp

# Phase 4: the E2E layer is a CLIENT-ONLY concern. The server is deliberately
# NOT linked against e2e.cpp -- it must stay cryptographically unaware of the
# client-to-client layer and merely relay opaque payloads.
CLIENT_SRC := $(COMMON) e2e.cpp

IP ?= 127.0.0.1

all: server client dh_test tamper_proxy mitm_proxy mitm_proxy_p3 e2e_test

server: server.cpp $(COMMON) dh.h crypto.h net.h certs.h
	$(CXX) $(CXXFLAGS) server.cpp $(COMMON) -o server $(LDLIBS)

client: client.cpp $(CLIENT_SRC) dh.h crypto.h net.h certs.h e2e.h
	$(CXX) $(CXXFLAGS) client.cpp $(CLIENT_SRC) -o client $(LDLIBS)

dh_test: dh_test.cpp dh.cpp net.cpp dh.h net.h
	$(CXX) $(CXXFLAGS) dh_test.cpp dh.cpp net.cpp -o dh_test $(LDLIBS)

tamper_proxy: tamper_proxy.cpp net.cpp net.h
	$(CXX) $(CXXFLAGS) tamper_proxy.cpp net.cpp -o tamper_proxy $(LDLIBS)

# Phase 4 Checkpoints 1-2: offline test for the E2E primitives (Base64 +
# in-memory AES-256-GCM) and the C1<->C2 DH session establishment.
# Links dh.cpp and crypto.cpp because the session layer REUSES the project's
# existing custom DH and KDF/fingerprint unchanged. No sockets are involved:
# net.cpp is pulled in only to satisfy crypto.cpp's link-time reference.
e2e_test: e2e_test.cpp e2e.cpp dh.cpp crypto.cpp net.cpp e2e.h dh.h crypto.h
	$(CXX) $(CXXFLAGS) e2e_test.cpp e2e.cpp dh.cpp crypto.cpp net.cpp -o e2e_test $(LDLIBS)

# Phase 2 MITM: succeeds against unauthenticated DH. Kept unchanged as the
# "before" evidence for the Phase 3 contrast.
mitm_proxy: mitm_proxy.cpp dh.cpp crypto.cpp net.cpp dh.h crypto.h net.h
	$(CXX) $(CXXFLAGS) mitm_proxy.cpp dh.cpp crypto.cpp net.cpp -o mitm_proxy $(LDLIBS)

# Phase 3 attack driver: presents a certificate to the victim and is defeated
# by validation (mode fake) or by proof-of-possession (mode copied).
mitm_proxy_p3: mitm_proxy_p3.cpp dh.cpp crypto.cpp net.cpp certs.cpp dh.h crypto.h net.h certs.h
	$(CXX) $(CXXFLAGS) mitm_proxy_p3.cpp dh.cpp crypto.cpp net.cpp certs.cpp -o mitm_proxy_p3 $(LDLIBS)

# Generate the CA and server certificate (server IP in the SAN).
certs:
	./gen_certs.sh $(IP)

check: all
	@echo "== running the DH test harness =="
	@./dh_test
	@echo
	@echo "== running the E2E test harness (Phase 4 checkpoints 1-2) =="
	@./e2e_test
	@echo
	@echo "== prohibited DH/ECDH/TLS API scan (expect no matches) =="
	@! grep -rn -E '^[[:space:]]*#[[:space:]]*include[[:space:]]*<openssl/(dh|dhx|ssl|tls1)\.h>|DH_new\(|DH_generate_key\(|DH_compute_key\(|DH_get_2048|EVP_PKEY_derive\(|ECDH_compute_key\(|SSL_CTX_new\(|SSL_connect\(|SSL_read\(|SSL_write\(' *.cpp *.h || (echo "PROHIBITED API FOUND"; exit 1)
	@echo "clean: no OpenSSL DH/ECDH exchange API or TLS present"
	@echo
	@echo "== BN_mod_exp is the sanctioned generic primitive (per TA clarification) =="
	@echo "   files that call it:"
	@grep -ln "BN_mod_exp" *.cpp || true

clean:
	rm -f server client dh_test tamper_proxy mitm_proxy mitm_proxy_p3 e2e_test

.PHONY: all certs check clean
