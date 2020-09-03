
# Azure KeyVault #

```
docker run -it --rm -v $HOME/.aws/credentials:/root/.aws/credentials -e "AZURE_CLIENT_ID=$AZURE_CLIENT_ID" -e "AZURE_TENANT_ID=19c3aeac-7d8a-4c9e-80b9-9f9510adc7f7" -e "AZURE_VAULT_NAME=ca-dev" -e "AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET" -e "AZURE_SUBSCRIPTION_ID=c120b3e7-49a6-46d4-a59f-cf9f3e767059" -e "AZURE_KEYVAULT_KID=69f33c7a3e4343a1847bac4450247234" docker.pkg.github.com/bernard-wagner/kms11mod:latest
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
cat << EOF | openssl
engine dynamic -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so -pre  LIST_ADD:1 -pre ID:pkcs11 -pre LOAD -pre MODULE_PATH:/var/lib/kms11/libpkcs11azure.so -pre VERBOSE
req -config openssl.conf -nodes -new -sha256 -engine pkcs11 -keyform engine -key "pkcs11:object=$AZURE_KEYVAULT_KID"
EOF
```
