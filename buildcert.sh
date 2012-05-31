#!/bin/sh
# Helper script to generate Self-signed certificates
# Mochiweb uses the certificate to start HTTPs listener

if [ ! -f "$HOSTNAME.self.key" ]; then
    echo "RSA key doesn't exist. Generating new one..."
    ssh-keygen -t rsa -f  $HOSTNAME.self.key -N ""
    RES=$?
    if [ $RES != 0 ]; then
        echo "Key generation has failed with Error $RES!"
        exit $RES
    fi
fi

if [ ! -f "$HOSTNAME.self.csr" ]; then
    echo "Certificate Self signing request doesn't exist. Generating new one..."
    echo $HOSTNAME
    openssl req -new -key $HOSTNAME.self.key -out $HOSTNAME.self.csr
    RES=$?
    if [ $RES != 0 ]; then
        echo "CRS generation has failed with Error $RES!"
        exit $RES
    fi
fi

if [ ! -f "$HOSTNAME.self.crt" ]; then
    echo "Certificate doesn't exist. Generating new one..."
    openssl x509 -req -days 365 -in $HOSTNAME.self.csr -signkey $HOSTNAME.self.key -out $HOSTNAME.self.crt
    RES=$?
    if [ $RES != 0 ]; then
        echo "Certificate generation has failed with Error $RES!"
        exit $RES
    fi
fi
