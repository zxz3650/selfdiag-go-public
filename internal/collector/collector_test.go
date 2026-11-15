//go:build linux || darwin

package collector

import (
	"context"
	"testing"
	"time"
)

func TestTimeoutKillsPipeHoldingChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, status, _ := command(ctx, []string{"/bin/sh", "-c", "sleep 10 & wait"})
	if status != "timeout" || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout failed: %s %s", status, time.Since(start))
	}
}

func TestMissingCommandIsUnsupported(t *testing.T) {
	_, status, _ := command(context.Background(), []string{"selfdiag-no-such-program-987654"})
	if status != "unsupported" {
		t.Fatalf("status=%s", status)
	}
}
