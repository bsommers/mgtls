//go:build !unix

package store

// lockFile is a no-op on platforms without flock(2); only the in-process mutex applies.
// Avoid running several mgtls processes against one store on these platforms.
func lockFile(string) (func(), error) { return func() {}, nil }
