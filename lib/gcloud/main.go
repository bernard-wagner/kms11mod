package main

import (
	"context"
	"os"
	"strconv"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/sirupsen/logrus"
	"github.com/bernard-wagner/kms11mod/internal/backend"
	"github.com/bernard-wagner/kms11mod/pkcs11mod"
	"google.golang.org/api/option"
)

func init() {
	if env := os.Getenv("GOOGLE_VERBOSE_LOGGING"); env != "" {
		if i, err := strconv.Atoi(env); err == nil {
			if i > 0 {
				logrus.SetLevel(logrus.TraceLevel)
				logrus.SetReportCaller(true)
			}
		}
	}

	ctx := context.Background()
	opts := []option.ClientOption{}

	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		logrus.WithError(err).Error("failed to initialize google client")
		return
	}

	project := os.Getenv("GOOGLE_PROJECT_ID")
	if project == "" {
		logrus.Error("GOOGLE_PROJECT_ID is not set")
	}
	location := os.Getenv("GOOGLE_LOCATION")
	if location == "" {
		logrus.Error("GOOGLE_LOCATION is not set")
	}

	pkcs11mod.SetBackend(backend.NewToken(&GoogleToken{
		client:     client,
		project:    project,
		location:   location,
		keyRing:    os.Getenv("GOOGLE_KEY_RING"),
		keyName:    os.Getenv("GOOGLE_KEY_NAME"),
		keyVersion: os.Getenv("GOOGLE_KEY_VERSION"),
	}))
}

func main() {

}
