package main

import (
	"crypto"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type digestFunc func(digest []byte) *kmspb.Digest

var (
	sha256DigestFunc = func(digest []byte) *kmspb.Digest {
		return &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		}
	}

	sha384DigestFunc = func(digest []byte) *kmspb.Digest {
		return &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest,
			},
		}
	}

	sha512DigestFunc = func(digest []byte) *kmspb.Digest {
		return &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest,
			},
		}
	}
)

var cryptoHashDigests = map[crypto.Hash]digestFunc{
	crypto.SHA256: sha256DigestFunc,
	crypto.SHA384: sha384DigestFunc,
	crypto.SHA512: sha512DigestFunc,
}
