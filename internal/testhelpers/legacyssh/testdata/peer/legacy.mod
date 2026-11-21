// Selected only when building this historical test peer. Keeping this named
// legacy.mod, not go.mod, includes its source in upterm's public module zip.
module github.com/owenthereal/upterm

go 1.26.0

require golang.org/x/crypto v0.58.0

require golang.org/x/sys v0.49.0 // indirect
