package emitter

import "path"

// Test returns boolean value to indicate that given pattern is valid.
//
// What is it for?
// Internally `emitter` uses `path.Match` function to find matching. But
// as this functionality is optional `Emitter` don't indicate that the
// pattern is invalid. You should check it separately explicitly via
// `Test` function.
func Test(pattern string) bool {
	_, err := path.Match(pattern, "---")
	return err == nil
}
