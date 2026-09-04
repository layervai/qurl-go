package sessioncookie

import (
	"errors"
	"testing"

	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

func TestParseErrorCarriesMalformedReplyTaxonomy(t *testing.T) {
	_, err := Parse([]byte(`{}`), 1)
	var classified *Error
	if !errors.Is(err, nhpwire.ErrMalformedReply) || !errors.As(err, &classified) || classified.Class != RejectBodyParse {
		t.Fatalf("Parse error = %T %v", err, err)
	}
}
