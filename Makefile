
GOOS=$$GOOS

LIB_EXT := so
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIB_EXT := dylib
endif

.PHONY: build all pkcs11mod

build-kms: pkcs11mod
	CGO_ENABLED=1 go build -mod=vendor -buildmode c-shared -ldflags "-w" -o libkms11mod-gcloud.$(LIB_EXT) lib/gcloud/*

build-azure: pkcs11mod
	CGO_ENABLED=1 go build -mod=vendor -buildmode c-shared -ldflags "-w" -o libkms11mod-azure.$(LIB_EXT) lib/azure/*

build-aws: pkcs11mod
	CGO_ENABLED=1 go build -mod=vendor -buildmode c-shared -ldflags "-w" -o libkms11mod-aws.$(LIB_EXT) lib/aws/*

pkcs11mod:
	make -C pkcs11mod build

test:
	go test -mod=vendor -v ./...

all: pkcs11mod build-kms build-azure build-aws
