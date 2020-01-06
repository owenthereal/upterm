package rollrus

import (
	"fmt"

	"github.com/rollbar/rollbar-go"
	"github.com/sirupsen/logrus"
)

var defaultTriggerLevels = []logrus.Level{
	logrus.ErrorLevel,
	logrus.FatalLevel,
	logrus.PanicLevel,
}

// wellKnownErrorFields are the names of the fields to be checked for values of
// type `error`, in priority order.
var wellKnownErrorFields = []string{
	logrus.ErrorKey, "err",
}

// NewHook creates a hook that is intended for use with your own logrus.Logger
// instance. Uses the default report levels defined in wellKnownErrorFields.
func NewHook(token string, env string, opts ...OptionFunc) *Hook {
	h := NewHookForLevels(token, env, defaultTriggerLevels)

	for _, o := range opts {
		o(h)
	}

	return h
}

// SetupLogging for use on Heroku. If token is not an empty string a Rollbar
// hook is added with the environment set to env. The log formatter is set to a
// TextFormatter with timestamps disabled.
func SetupLogging(token, env string) {
	setupLogging(token, env, defaultTriggerLevels)
}

// SetupLoggingForLevels works like SetupLogging, but allows you to
// set the levels on which to trigger this hook.
func SetupLoggingForLevels(token, env string, levels []logrus.Level) {
	setupLogging(token, env, levels)
}

func setupLogging(token, env string, levels []logrus.Level) {
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	if token != "" {
		logrus.AddHook(NewHookForLevels(token, env, levels))
	}
}

// ReportPanic attempts to report the panic to Rollbar using the provided
// client and then re-panic. If it can't report the panic it will print an
// error to stderr.
func ReportPanic(token, env string) {
	if token != "" {
		if p := recover(); p != nil {
			defer panic(p)
			r := rollbar.New(token, env, "", "", "")
			r.ErrorWithLevel(rollbar.CRIT, fmt.Errorf("panic: %q", p))
			r.Wait()
		}
	}
}
