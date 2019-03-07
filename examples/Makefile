
INC_DIR 										:= ../include
OPENSSL_LIB_DIR 						:= ../
TLSAbstractionLayer_LIB_DIR := ../build

INC_FLAGS										:= -I $(INC_DIR)
LD_FLAGS										:= -L $(OPENSSL_LIB_DIR) -l:libcrypto.so.1.1 -l:libssl.so.1.1 \
															 -L $(TLSAbstractionLayer_LIB_DIR) -l:libtlsabstractionlayer.so.1.0

all: client server dtls_client dtls_server

client:
	$(CXX) client.cpp $(INC_FLAGS) $(LD_FLAGS) -o client.exe

server:
	$(CXX) server.cpp $(INC_FLAGS) $(LD_FLAGS) -o server.exe

dtls_client:
	$(CXX) dtls_client.cpp $(INC_FLAGS) $(LD_FLAGS) -o dtls_client.exe

dtls_server:
	$(CXX) dtls_server.cpp $(INC_FLAGS) $(LD_FLAGS) -o dtls_server.exe
