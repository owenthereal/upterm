// Package tty answers two questions about a file that may be a terminal:
// whether this process may touch it, and how big it is. It lives at the
// module root's internal/ so that both cmd/ and host/ may import it; Go's
// internal rule confines host/internal to the tree under host/.
package tty
