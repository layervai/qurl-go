package relayknock

import "time"

// nowUnixNano is the send timestamp for a knock, matching the Go server's
// time.Now().UnixNano(). Wrapped so the time dependency stays in one place.
func nowUnixNano() uint64 { return uint64(time.Now().UnixNano()) }
