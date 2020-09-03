FROM golang:1.13

WORKDIR /src

COPY . /src

RUN make all

FROM debian:sid

RUN apt-get update && apt-get install -y libengine-pkcs11-openssl openssl gnutls-bin opensc ca-certificates gridsite-clients gnupg gnupg-pkcs11-scd scdaemon

COPY --from=0 /src/libkms11mod-aws.so /var/lib/kms11/libkms11mod-aws.so

COPY --from=0 /src/libkms11mod-azure.so /var/lib/kms11/libkms11mod-azure.so

COPY --from=0 /src/libkms11mod-gcloud.so /var/lib/kms11/libkms11mod-gcloud.so

COPY build/gpg-agent.conf /root/.gnupg/gpg-agent.conf

COPY build/gnupg-pkcs11-scd.conf  /root/.gnupg/gnupg-pkcs11-scd.conf

COPY build/gpg.conf  /root/.gnupg/gpg.conf

ENTRYPOINT ["/bin/bash"]