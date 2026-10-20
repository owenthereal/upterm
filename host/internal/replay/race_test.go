//go:build race

package replay

// timeScale stretches the tests' timing bounds by about how much slower the
// race detector makes the code they time.
const timeScale = 10
