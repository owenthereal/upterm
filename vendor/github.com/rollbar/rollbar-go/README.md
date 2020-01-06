# rollbar-go
[![Build Status](https://travis-ci.org/rollbar/rollbar-go.svg?branch=master)](https://travis-ci.org/rollbar/rollbar-go)

[Rollbar](https://rollbar.com) is a real-time exception reporting service for Go
and other languages. The Rollbar service will alert you of problems with your code
and help you understand them in a ways never possible before. We love it and we hope
you will too.

rollbar-go is a Golang Rollbar client that makes it easy to report errors to
Rollbar with full stacktraces. Errors are sent to Rollbar asynchronously in a
background goroutine.

Because Go's `error` type doesn't include stack information from when it was set
or allocated, we use the stack information from where the error was reported.

# Setup Instructions and Usage

1. [Sign up for a Rollbar account](https://rollbar.com/signup)
2. Follow the [Usage](https://docs.rollbar.com/docs/go#usage) example in our [Go SDK docs](https://docs.rollbar.com/docs/go) 
to get started for your platform.

# Documentation

[API docs on godoc.org](http://godoc.org/github.com/rollbar/rollbar-go)

# Running Tests

[Running tests docs on docs.rollar.com](https://docs.rollbar.com/docs/go#section-running-tests)

# Release History & Changelog

See our [Releases](https://github.com/rollbar/rollbar-go/releases) page for a list of all releases, including changes.

# Help / Support

If you run into any issues, please email us at [support@rollbar.com](mailto:support@rollbar.com)

For bug reports, please [open an issue on GitHub](https://github.com/rollbar/rollbar-go/issues/new).

# Contributing

1. Fork it
2. Create your feature branch (```git checkout -b my-new-feature```).
3. Commit your changes (```git commit -am 'Added some feature'```)
4. Push to the branch (```git push origin my-new-feature```)
5. Create new Pull Request

# History

This library originated with this project
[github.com/stvp/rollbar](https://github.com/stvp/rollbar).
This was subsequently forked by Heroku, [github.com/heroku/rollbar](https://github.com/heroku/rollbar),
and extended. Those two libraries diverged as features were added independently to both. This
official library is actually a fork of the Heroku fork with some git magic to make it appear as a
standalone repository along with all of that history. We then also went back to the original stvp
library and brought over most of the divergent changes. Since then we have moved forward to add more
functionality to this library and it is the recommended notifier for Go going forward.