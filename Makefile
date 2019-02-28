TLSAbstractionLayer_INCDIR 			 := ./include
TLSAbstractionLayer_SRC_DIR 		 := ./src
OPENSSL_INC_DIR 					 := ./include
BUILD_DIR 							 := ./build
TLSAbstractionLayer_SRC 			 := $(shell find $(TLSAbstractionLayer_SRC_DIR) -iname *.cpp)
OBJS                 				 := $(patsubst %.cpp,%.o,$(TLSAbstractionLayer_SRC))

INC_FLAGS 				             := -I $(TLSAbstractionLayer_INCDIR) -I $(OPENSSL_INC_DIR)
CXX_FLAGS 					         := -Wall -Werror -fpic

RM	= rm -rf

all: sharedlib examples

examples: sharedlib
	make -C ./examples

sharedlib: $(OBJS)
	$(CXX) -shared -o ./build/libtlsabstractionlayer.so.1.0 $(BUILD_DIR)/*.o

$(OBJS):%.o: %.cpp
	$(CXX) $(INC_FLAGS) -c $(CXX_FLAGS) $< -o $(BUILD_DIR)/$(@F)

clean :
	$(RM) $(BUILD_DIR)/*
