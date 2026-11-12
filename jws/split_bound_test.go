package jws

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestVerify_RefusesATokenOfManySegmentsWithoutSplittingEachOne(t *testing.T) {
	token := strings.Repeat(".", 1<<20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := Verify(context.Background(), token, nil, nil)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, joseerror.ErrMalformedToken) {
		t.Fatalf("[RFC 7515 7.1] a JWS Compact Serialization has three segments, so want ErrMalformedToken, got %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<16 {
		t.Errorf("[RFC 7515 7.1] the segment count is known after the fourth segment, so refusing %d dots must not allocate per segment, allocated %d bytes", len(token), allocated)
	}
}
