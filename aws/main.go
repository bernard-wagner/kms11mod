package main

import (
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/sirupsen/logrus"
	"github.com/bernard-wagner/kms11mod/kms11"
	"github.com/bernard-wagner/kms11mod/pkcs11mod"
)

func init() {
	if env := os.Getenv("AWS_VERBOSE_LOGGING"); env != "" {
		if i, err := strconv.Atoi(env); err == nil {
			if i > 0 {
				logrus.SetLevel(logrus.TraceLevel)
				logrus.SetReportCaller(true)
			}
		}
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})

	if err != nil {
		logrus.WithError(err).Trace("failed to get settings from environment")
		return
	}

	pkcs11mod.SetBackend(kms11.NewToken(&AWSKMSToken{
		client: kms.New(sess),
	}))
}

func main() {

}
