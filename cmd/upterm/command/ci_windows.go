package command

// ciRootContinueFile is the default continue file on Windows.
//
// `touch /continue` typed into the session's shell is what a guest reaches for,
// and on a runner that shell is MSYS2 bash, whose root is the MSYS2 install
// directory. So the path to watch for is the native spelling of that: a guest
// writing "/continue" in bash creates C:\msys64\continue, and nothing native
// would ever see a file at the filesystem root. Hardcoded to the same location
// action-upterm uses, which is where the runner images put MSYS2.
const ciRootContinueFile = `C:\msys64\continue`
