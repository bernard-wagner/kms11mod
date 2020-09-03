

# Google KMS #

## Configuration ##

```
docker run -it --rm -v $HOME/.config/gcloud:/root/.config/gcloud -e "GOOGLE_KEY_ID=$GOOGLE_KEY_ID"  docker.pkg.github.com/bernard-wagner/kms11mod:latest
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
```

```
regex='^projects\/([^\/]+)\/locations\/([^\/]+)\/keyRings\/([^\/]+)\/cryptoKeys\/([^\/]+)\/.*'

[[ $GOOGLE_KEY_ID =~ $regex ]]
export GOOGLE_PROJECT_ID=${BASH_REMATCH[1]}
export GOOGLE_LOCATION=${BASH_REMATCH[2]}
export GOOGLE_KEY_RING=${BASH_REMATCH[3]}
export GOOGLE_KEY_NAME=${BASH_REMATCH[4]}
export GOOGLE_KEY_URI=$(urlencode $GOOGLE_KEY_ID)
```

```
cat << EOF | openssl
engine dynamic -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so -pre  LIST_ADD:1 -pre ID:pkcs11 -pre LOAD -pre MODULE_PATH:/var/lib/kms11/libpkcs11gcloud.so -pre VERBOSE
req -config openssl.conf -nodes -new -sha256 -engine pkcs11 -keyform engine -key "pkcs11:object=$GOOGLE_KEY_URI"
EOF
```

