
INC_DIR 										:= ../include
OPENSSL_LIB_DIR 						:= ../
TLSAbstractionLayer_LIB_DIR := ../build

INC_FLAGS										:= -I $(INC_DIR)
LD_FLAGS										:= -L $(OPENSSL_LIB_DIR) -l:libcrypto.so.1.1 -l:libssl.so.1.1 \
															 -L $(TLSAbstractionLayer_LIB_DIR) -l:libtlsabstractionlayer.so.1.0

all: client server

client:
	$(CXX) client.cpp $(INC_FLAGS) $(LD_FLAGS) -o client.exe

server:
	$(CXX) server.cpp $(INC_FLAGS) $(LD_FLAGS) -o server.exe
