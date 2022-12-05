[![CircleCI](https://circleci.com/gh/heroku/rollrus.svg?style=svg)](https://circleci.com/gh/heroku/rollrus)&nbsp;[![GoDoc](https://godoc.org/github.com/heroku/rollrus?status.svg)](https://godoc.org/github.com/heroku/rollrus)

# What

Rollrus is what happens when [Logrus](https://github.com/sirupsen/logrus) meets [Rollbar](github.com/rollbar/rollbar-go).

Install the hook into a Logrus logger to report logged messages to Rollbar.
By default, only messages with the Error, Fatal, or Panic level are reported.

Panic and Fatal errors are reported synchronously to help ensure that logs are delivered before the process exits.
All other messages are delivered in the background, and may be dropped if the queue is full.

If the error includes a [`StackTrace`](https://godoc.org/github.com/pkg/errors#StackTrace), that `StackTrace` is reported to rollbar.

# Usage

Examples available in the [tests](https://github.com/heroku/rollrus/blob/master/examples_test.go) or on [GoDoc](https://godoc.org/github.com/heroku/rollrus).
