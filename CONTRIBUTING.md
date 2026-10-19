# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this repository before making a change. 

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a 
   build.
2. Update the README.md with details of changes to the interface, this includes new environment 
   variables, exposed ports, useful file locations and container parameters.
3. Increase the version numbers in any examples files and the README.md to the new version that this
   Pull Request would represent. The versioning scheme we use is [SemVer](http://semver.org/).
4. You may merge the Pull Request in once you have the sign-off of two other developers, or if you 
   do not have permission to do that, you may request the second reviewer to merge it for you.

## Tests

A test must pass or fail on what the code does, not on how fast the machine running it is.

**Run timing in a bubble.** A test of anything timer-driven runs its whole body in
[`synctest.Test`](https://pkg.go.dev/testing/synctest) and makes its fakes, channels, timers and
listeners inside it. There, settling and advancing are different things. `synctest.Wait()` returns
once every other goroutine in the bubble is blocked: it runs what is due now and never moves the
clock. The clock moves only when every goroutine, the test's included, is blocked, which in practice
means the test calls `time.Sleep` or waits on a channel. So an immediate consequence is act,
`synctest.Wait()`, assert; a timer-driven one is `time.Sleep(d)`, `synctest.Wait()`, assert; and a
deadline is checked on both sides, as Go's `ContextWithTimeout` example does:

```go
time.Sleep(timeout - time.Nanosecond)
synctest.Wait() // everything due before the timeout has run
require.False(t, fired(), "fired before its timeout")
time.Sleep(time.Nanosecond)
synctest.Wait() // the timeout's own work has run
require.True(t, fired(), "didn't fire at its timeout")
```

Comment each `synctest.Wait()` with what it has settled. `t.Run` isn't allowed in a bubble, so each
subtest calls `synctest.Test` itself. A goroutine blocked on a real socket, a pty, a child process,
a file or a `sync.Mutex` doesn't count as blocked, so a test that needs one stays on the real clock,
as does one that checks a monotonic clock reading, which a bubble's `time.Now` doesn't carry.

**Keep the timing relationship.** A timing test tells correct code from broken code by an
inequality, such as "a piece every 100 ms < the 200 ms stall timeout < the length of the run".
Write it in the test's comment, and keep it when you change either side: set the instance's
timing, or rescale the workload, but don't just drop an override. Break the code the test guards
and check that the test fails, rather than hangs.

**Wait on signals, not polls.** Outside a bubble, wait for a signal from the component that makes
the change, not for a condition to come true with `Eventually` or a sleep. To show something didn't
happen, assert after a signal proving it would have by then. `Eventually` is only for a process or
server boundary, with a comment naming which.

**Put timing and hooks on the instance.** Give a component its timeouts, and any hook read on a
goroutine that can outlive a test, as fields set when it is made; a zero value means the default.
Set those fields in a test, never a package-level variable that production code reads.

**Every goroutine a fixture starts can exit.** `synctest.Test` waits for all of them. A fixture
closes what it owns (pipes, listeners, connections) and releases every gate it holds, idempotently,
in a `t.Cleanup` registered inside the bubble, so that a failed assertion fails only its own test,
rather than ending in a deadlock panic that stops the whole test binary. A fake that broken code
could call in a loop at one instant counts its calls and stops the code past a cap, so the test
fails instead of hanging.

**Give every goroutine a component starts one owner**, whose stop waits for it, with a bound, and
have the owner close the connection it owns. Where a goroutine is parked in a call its owner can't
interrupt, say in a comment what ends it, as AsyncWriter's drain, Watch's probe and the lease
keeper's abandoned call do. **Have the actor that knows an outcome record it:** a group of
goroutines returning says only that the group stopped, not why.

**Test orderings at checkpoints.** A test of a race holds the code at the points inside the bug,
such as "transaction committed" or "reply held", not around the method calls. Each gate signals its
arrival, and the test releases the next step only after that signal. Run every order the code
allows, and check the invariant in each.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to making participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

* Using welcoming and inclusive language
* Being respectful of differing viewpoints and experiences
* Gracefully accepting constructive criticism
* Focusing on what is best for the community
* Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery and unwelcome sexual attention or
advances
* Trolling, insulting/derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or electronic
  address, without explicit permission
* Other conduct which could reasonably be considered inappropriate in a
  professional setting

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable
behavior and are expected to take appropriate and fair corrective action in
response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this Code of Conduct, or to ban temporarily or
permanently any contributor for other behaviors that they deem inappropriate,
threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by [contacting GitHub Support](https://support.github.com/contact/report-abuse).
GitHub reviews those reports under its
[Acceptable Use Policies](https://docs.github.com/site-policy/acceptable-use-policies/github-acceptable-use-policies)
and can act directly on accounts and content, including in this repository;
confidentiality is handled as part of that process, by GitHub rather than by the
maintainers.

For conduct GitHub cannot reach — at an event, or on another platform — ask a
maintainer to make contact by opening a private report through the
[Security tab](https://github.com/owenthereal/upterm/security/advisories/new).
That form is labelled for vulnerabilities, but it is the private channel to the
maintainers; you do not need to include any details in it to get a reply.

Security vulnerabilities are not conduct reports: see [SECURITY.md](SECURITY.md).

Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good
faith may face temporary or permanent repercussions as determined by other
members of the project's leadership.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 1.4,
available at [http://contributor-covenant.org/version/1/4][version]

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/
