
INC_DIR 										:= ../include
OPENSSL_LIB_DIR 						:= ../
TLSAbstractionLayer_LIB_DIR := ../build

INC_FLAGS										:= -I $(INC_DIR)
LD_FLAGS										:= -L $(OPENSSL_LIB_DIR) -l:libcrypto.so.1.1 -l:libssl.so.1.1 \
															 -L $(TLSAbstractionLayer_LIB_DIR) -l:libtlsabstractionlayer.so.1.0

SRCS       := $(shell ls *.cpp)
OBJS       := $(patsubst %.cpp,%.o,$(SRCS))
EXEC       := $(patsubst %.cpp,%.exe,$(SRCS))

all: $(EXEC)

$(EXEC):%.exe: %.o
	$(CXX) $< -o ./$(@F) $(LD_FLAGS)

$(OBJS):%.o: %.cpp
	$(CXX) $(INC_FLAGS) -c $< -o ./$(@F)

clean:
	rm *.o *.exe
