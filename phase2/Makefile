CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pthread
LDLIBS   := -lcrypto -pthread

COMMON   := dh.cpp crypto.cpp net.cpp

all: server client dh_test tamper_proxy mitm_proxy

server: server.cpp $(COMMON) dh.h crypto.h net.h
	$(CXX) $(CXXFLAGS) server.cpp $(COMMON) -o server $(LDLIBS)

client: client.cpp $(COMMON) dh.h crypto.h net.h
	$(CXX) $(CXXFLAGS) client.cpp $(COMMON) -o client $(LDLIBS)

dh_test: dh_test.cpp dh.cpp net.cpp dh.h net.h
	$(CXX) $(CXXFLAGS) dh_test.cpp dh.cpp net.cpp -o dh_test $(LDLIBS)

tamper_proxy: tamper_proxy.cpp net.cpp net.h
	$(CXX) $(CXXFLAGS) tamper_proxy.cpp net.cpp -o tamper_proxy $(LDLIBS)

mitm_proxy: mitm_proxy.cpp $(COMMON) dh.h crypto.h net.h
	$(CXX) $(CXXFLAGS) mitm_proxy.cpp $(COMMON) -o mitm_proxy $(LDLIBS)

# Run the tests and check for prohibited APIs
check: all
	@echo "== running the DH test harness =="
	@./dh_test
	@echo
	@echo "== prohibited DH/ECDH/TLS API scan (expect no matches) =="
	@! grep -rn -E '^[[:space:]]*#[[:space:]]*include[[:space:]]*<openssl/(dh|dhx|ec|ecdh|ssl|tls1)\.h>|DH_new\(|DH_generate_key\(|DH_compute_key\(|DH_get_2048|EVP_PKEY_derive\(|EVP_PKEY_CTX_new_id\(|ECDH_compute_key\(|SSL_CTX_new\(|SSL_connect\(' *.cpp *.h || (echo "PROHIBITED API FOUND"; exit 1)
	@echo "clean: no OpenSSL DH/ECDH exchange API or TLS present"
	@echo
	@echo "== BN_mod_exp is the sanctioned generic primitive (per TA clarification) =="
	@echo "   it evaluates base^exp mod m only; the DH protocol is in dh.cpp."
	@echo "   files that call it:"
	@grep -ln "BN_mod_exp" *.cpp || true

clean:
	rm -f server client dh_test tamper_proxy mitm_proxy

.PHONY: all check clean