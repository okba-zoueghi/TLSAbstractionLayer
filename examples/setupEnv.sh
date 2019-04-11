#! /bin/bash

#Set the path of OpenSSL's libraries
export OPENSSL_LIB_DIR=../libs/openssl/

#Create symbolic links
ln -sfn libssl.so.1.1 ../libs/openssl/libssl.so
ln -sfn libcrypto.so.1.1 ../libs/openssl/libcrypto.so

#Set the path of WolfSSL library
export WOLFSSL_LIB_DIR=../libs/wolfssl/

#Create symbolic links
ln -sfn libwolfssl.so.19 ../libs/wolfssl/libwolfssl.so

#Export the libraries
export LD_LIBRARY_PATH=../build:$OPENSSL_LIB_DIR:$WOLFSSL_LIB_DIR:$LD_LIBRARY_PATH
