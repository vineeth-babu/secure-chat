# CS6008 Phase 3

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pthread
LDLIBS   := -lcrypto -pthread

COMMON   := dh.cpp crypto.cpp net.cpp certs.cpp

IP ?= 127.0.0.1

all: server client dh_test tamper_proxy mitm_proxy mitm_proxy_p3

server: server.cpp $(COMMON) dh.h crypto.h net.h certs.h
	$(CXX) $(CXXFLAGS) server.cpp $(COMMON) -o server $(LDLIBS)

client: client.cpp $(COMMON) dh.h crypto.h net.h certs.h
	$(CXX) $(CXXFLAGS) client.cpp $(COMMON) -o client $(LDLIBS)

dh_test: dh_test.cpp dh.cpp net.cpp dh.h net.h
	$(CXX) $(CXXFLAGS) dh_test.cpp dh.cpp net.cpp -o dh_test $(LDLIBS)

tamper_proxy: tamper_proxy.cpp net.cpp net.h
	$(CXX) $(CXXFLAGS) tamper_proxy.cpp net.cpp -o tamper_proxy $(LDLIBS)

mitm_proxy: mitm_proxy.cpp dh.cpp crypto.cpp net.cpp dh.h crypto.h net.h
	$(CXX) $(CXXFLAGS) mitm_proxy.cpp dh.cpp crypto.cpp net.cpp -o mitm_proxy $(LDLIBS)

mitm_proxy_p3: mitm_proxy_p3.cpp dh.cpp crypto.cpp net.cpp certs.cpp dh.h crypto.h net.h certs.h
	$(CXX) $(CXXFLAGS) mitm_proxy_p3.cpp dh.cpp crypto.cpp net.cpp certs.cpp -o mitm_proxy_p3 $(LDLIBS)

# Generate the CA and server certificate.
certs:
	./gen_certs.sh $(IP)

check: all
	@echo "== running DH tests =="
	@./dh_test
	@echo
	@echo "== checking for unsupported APIs =="
	@! grep -rn -E '^[[:space:]]*#[[:space:]]*include[[:space:]]*<openssl/(dh|dhx|ssl|tls1)\.h>|DH_new\(|DH_generate_key\(|DH_compute_key\(|DH_get_2048|EVP_PKEY_derive\(|ECDH_compute_key\(|SSL_CTX_new\(|SSL_connect\(|SSL_read\(|SSL_write\(' *.cpp *.h || (echo "Unsupported API found"; exit 1)
	@echo "No unsupported DH/ECDH or TLS APIs found"
	@echo
	@echo "== BN_mod_exp usage =="
	@echo "   files that call it:"
	@grep -ln "BN_mod_exp" *.cpp || true

clean:
	rm -f server client dh_test tamper_proxy mitm_proxy mitm_proxy_p3

.PHONY: all certs check clean