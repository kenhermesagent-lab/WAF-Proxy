package updates

import "os"

// Kept behind small vars so tests can exercise the protocol without touching
// the host environment.
var osGetenv = os.Getenv
