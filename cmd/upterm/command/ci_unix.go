//go:build !windows

package command

// ciRootContinueFile is the default continue file: the path `touch /continue`
// writes, which is what action-upterm has documented for years and what anyone
// who has used it will type.
const ciRootContinueFile = "/continue"
