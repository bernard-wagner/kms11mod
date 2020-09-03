
GOOS=$$GOOS

.PHONY: build all pkcs11mod

build-kms: pkcs11mod
	CGO_ENABLED=1 go build -mod=vendor -buildmode c-shared -ldflags "-w" -o libpkcs11gcloud.so gcloud/*

build-azure: pkcs11mod
	CGO_ENABLED=1 go build -mod=vendor -buildmode c-shared -ldflags "-w" -o libpkcs11azure.so azure/*

build-aws: pkcs11mod
	CGO_ENABLED=1 go build -mod=vendor -buildmode c-shared -ldflags "-w" -o libpkcs11aws.so aws/*

pkcs11mod:
	make -C pkcs11mod build

test:
	go test -mod=vendor -v ./...

all: pkcs11mod build-kms build-azure build-aws
