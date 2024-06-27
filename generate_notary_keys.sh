

# Root certificate
openssl req -newkey rsa:2048 -nodes -keyout fixture/tls/rootCA.key -x509 -days 365 -out fixture/tls/rootCA.crt -subj "/C=US/ST=L1/L=EigenLayer/O=Opacity/CN=OpacityNetwork" 2>/dev/null
openssl req -x509 -sha256 -new -nodes -key fixture/tls/rootCA.key -days 3650 -out fixture/tls/rootCA.pem -subj "/C=US/ST=L1/L=EigenLayer/O=Opacity/CN=OpacityNetwork" 2>/dev/null


# Notary certificate
openssl req -newkey rsa:2048 -nodes -days 365000 \
   -keyout fixture/tls/notary.key \
   -out fixture/tls/notary.csr \
   -subj "/C=US/ST=L1/L=EigenLayer/O=Opacity/CN=OpacityNetwork" 2>/dev/null


openssl x509 -req -days 365000 -set_serial 01 \
   -in fixture/tls/notary.csr \
   -out fixture/tls/notary.crt \
   -CA fixture/tls/rootCA.pem \
   -CAkey fixture/tls/rootCA.key \
   -extfile fixture/tls/notary.ext 2>/dev/null


openssl ecparam -name secp256r1 -genkey -noout -out fixture/notary/private-key 2>/dev/null
openssl pkcs8 -topk8 -inform PEM -outform PEM -in fixture/notary/private-key -out fixture/notary/notary.key -nocrypt 2>/dev/null
openssl ec -in fixture/notary/notary.key -pubout -out fixture/notary/notary.pub 2>/dev/null
rm fixture/notary/private-key 2>/dev/null