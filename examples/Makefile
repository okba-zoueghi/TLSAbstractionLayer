
INC_DIR 										:= ../include
TLSAbstractionLayer_LIB_DIR := ../build

INC_FLAGS										:= -I $(INC_DIR)
LD_FLAGS										:= -L $(TLSAbstractionLayer_LIB_DIR) -l:libtlsabstractionlayer.so.1.0 -L $(OPENSSL_LIB_DIR) -lssl -lcrypto  


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
