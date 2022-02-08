package common

import "io"

// Close is a helper function for absorbing errors in the `defer x.Close()` pattern
func Close(o io.Closer) {
	_ = o.Close()
}
