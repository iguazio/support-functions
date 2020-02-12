package main

import (
	"encoding/base64"
	"log"
	"os"
	"testing"

	"github.com/nuclio/logger"
	"github.com/nuclio/nuclio-sdk-go"
	"github.com/stretchr/testify/suite"
)

type Event struct {
	nuclio.AbstractEvent
}

type Logger struct {
	logger.Logger
}

type TestSuite struct {
	suite.Suite
	context *nuclio.Context
	event   *Event
}

func (ae *Event) GetFieldString(key string) string {
	switch key {
	case "kind":
		return "Security.User.Login.Succeeded"
	case "description":
		return "[$match].*successfully logged into.*"
	case "severity":
		return "info"
	case "last_events_amount":
		return "5"
	case "visibility":
		return "external"
	default:
		return ""
	}
}

func (Logger) Debug(format interface{}, vars ...interface{}) {
	log.Printf(format.(string), vars...)
}

func (Logger) ErrorWith(format interface{}, vars ...interface{}) {
	log.Printf(format.(string), vars...)
}

func (Logger) WarnWith(format interface{}, vars ...interface{}) {
	log.Printf(format.(string), vars...)
}

func (Logger) InfoWith(format interface{}, vars ...interface{}) {
	log.Printf(format.(string), vars...)
}

func (Logger) DebugWith(format interface{}, vars ...interface{}) {
	log.Printf(format.(string), vars...)
}

func (suite *TestSuite) SetupTest() {
	suite.Assert().NoError(nil)
	suite.context = &nuclio.Context{Logger: Logger{}}
	suite.event = &Event{}
	suite.Assert().NoError(InitContext(suite.context), "could not initialize context")
}

func (suite *TestSuite) SetupSuite() {
	systemPassword, err := base64.StdEncoding.DecodeString("bnVuM3pAaWd6")
	suite.Assert().NoError(err)

	osEnvs := map[string]string{
		"SYSTEMS_PASSWORD": string(systemPassword),
		"SYSTEMS_USERNAME": "igz_admin",
		"PROVAZIO_DEFAULT_ENV": "dev",
		"PROVAZIO_USE_REMOTE": "true",
	}
	for k, v := range osEnvs {
		suite.Require().NoError(os.Setenv(k, v))
	}

}

func (suite *TestSuite) TestHandler() {
	res, err := Handler(suite.context, suite.event)
	suite.Assert().NoError(err, "Response Error")
	log.Print(string(res.(nuclio.Response).Body))
}

func TestTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
