package rollrus

import "github.com/sirupsen/logrus"

// OptionFunc that can be passed to NewHook.
type OptionFunc func(*Hook)

// WithLevels is an OptionFunc that customizes the log.Levels the hook will
// report on.
func WithLevels(levels ...logrus.Level) OptionFunc {
	return func(h *Hook) {
		h.triggers = levels
	}
}

// WithMinLevel is an OptionFunc that customizes the log.Levels the hook will
// report on by selecting all levels more severe than the one provided.
func WithMinLevel(level logrus.Level) OptionFunc {
	var levels []logrus.Level
	for _, l := range logrus.AllLevels {
		if l <= level {
			levels = append(levels, l)
		}
	}

	return func(h *Hook) {
		h.triggers = levels
	}
}

// WithIgnoredErrors is an OptionFunc that whitelists certain errors to prevent
// them from firing. See https://golang.org/ref/spec#Comparison_operators
func WithIgnoredErrors(errors ...error) OptionFunc {
	return func(h *Hook) {
		h.ignoredErrors = append(h.ignoredErrors, errors...)
	}
}

// WithIgnoreErrorFunc is an OptionFunc that receives the error that is about
// to be logged and returns true/false if it wants to fire a Rollbar alert for.
func WithIgnoreErrorFunc(fn func(error) bool) OptionFunc {
	return func(h *Hook) {
		h.ignoreErrorFunc = fn
	}
}

// WithIgnoreFunc is an OptionFunc that receives the error and custom fields that are about
// to be logged and returns true/false if it wants to fire a Rollbar alert for.
func WithIgnoreFunc(fn func(err error, fields map[string]interface{}) bool) OptionFunc {
	return func(h *Hook) {
		h.ignoreFunc = fn
	}
}
