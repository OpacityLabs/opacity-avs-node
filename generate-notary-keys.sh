openssl ecparam -name secp256r1 -genkey -noout -out fixture/notary/private-key
openssl pkcs8 -topk8 -inform PEM -outform PEM -in fixture/notary/private-key -out fixture/notary/notary.key -nocrypt
openssl ec -in fixture/notary/notary.key -pubout -out fixture/notary/notary.pub
rm fixture/notary/private-key