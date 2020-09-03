# AWS Example Usage #

```
docker run -it --rm -v $HOME/.aws/credentials:/root/.aws/credentials -e "AWS_REGION=us-east-1" -e "AWS_KEY_ID=arn:aws:kms:us-east-1:043631429062:key/89e2b5b0-1b31-4c4b-b51a-25d3982cd0cb" docker.pkg.github.com/bernard-wagner/kms11mod:latest
```

## Generating CSR ##

```
cat << EOF > openssl.conf
[req]
prompt = no
distinguished_name  = req_distinguished_name
string_mask         = utf8only
req_extensions      = req_extensions
[req_distinguished_name]
C   = ZA
O   = ACME
OU  = ACME Certification Authority
CN  = ACME Issuing CA
[req_extensions]
EOF

cat << EOF | openssl
engine dynamic -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so  -pre  LIST_ADD:1 -pre ID:pkcs11 -pre LOAD -pre MODULE_PATH:/var/lib/kms11/libpkcs11aws.so -pre VERBOSE
req -config openssl.conf -nodes -new -sha256 -engine pkcs11 -keyform engine -key "pkcs11:object=$AWS_KEY_ID"
EOF
```
