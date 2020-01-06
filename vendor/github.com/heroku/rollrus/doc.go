package rollrus

// Package rollrus combines github.com/rollbar/rollbar-go with
// github.com/sirupsen/logrus via logrus.Hooks.  Whenever logrus'
// logger.Error/f(), logger.Fatal/f() or logger.Panic/f() are used the messages
// are intercepted and sent to rollbar.
//
// Use SetupLogging for basic use cases using the logrus singleton logger.
//
// Custom uses are supported by creating a new Hook (via NewHook) and
// registering it with your logrus Logger of choice.
//
// The levels can be customized with the WithLevels OptionFunc.
//
// Specific errors can be ignored with the WithIgnoredErrors OptionFunc. This is
// useful for ignoring errors such as context.Canceled.
//
// See the Examples in the tests for more usage.
