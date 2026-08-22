package relayknock

import "time"

// nowUnixMilli is the send timestamp for a knock, matching the Go server's
// time.Now().UnixMilli(). Wrapped so the time dependency stays in one place.
func nowUnixMilli() uint64 { return uint64(time.Now().UnixMilli()) }
