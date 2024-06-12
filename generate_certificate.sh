# openssl req -new -newkey rsa:1024 -nodes -out fixture/tls/notary.csr -keyout fixture/tls/notary.key
# openssl x509 -trustout -signkey fixture/tls/notary.key -days 365 -req -in fixture/tls/notary.csr -out fixture/tls/notary.pem
# openssl ca -policy policy_anything -keyfile fixture/tls/notary.key -cert fixture/tls/notary.pem -out test.pem -infiles fixture/tls/notary.csr


# Root certificate
openssl genrsa -out fixture/tls/rootCA.key 2048
openssl req -x509 -sha256 -new -nodes -key fixture/tls/rootCA.key -days 3650 -out fixture/tls/rootCA.pem


# Notary certificate

openssl req -newkey rsa:2048 -nodes -days 365000 \
   -keyout fixture/tls/notary.key \
   -out fixture/tls/notary.csr


openssl x509 -req -days 365000 -set_serial 01 \
   -in fixture/tls/notary.csr \
   -out fixture/tls/notary.crt \
   -CA fixture/tls/rootCA.pem \
   -CAkey fixture/tls/rootCA.key \
   -extfile fixture/tls/notary.ext
