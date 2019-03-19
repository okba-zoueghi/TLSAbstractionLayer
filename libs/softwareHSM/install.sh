#! /bin/sh

# Install softhsm library
mkdir -p /usr/local/lib/softhsm/
cp ./libsofthsm.so /usr/local/lib/softhsm/

# Install softhsm config file
cp ./softhsm.conf /etc/

# Create files for slots
mkdir -p /var/lib/softhsm/
touch /var/lib/softhsm/slot0.db
touch /var/lib/softhsm/slot1.db

# Install botan library
cp ./libbotan-1.10.so.1 /lib

# Install pkcs11 openssl engine
cp ./libpkcs11.so /lib

# Install openssl config file
mkdir -p /usr/local/ssl/
cp ./openssl.cnf /usr/local/ssl/

