package log

import (
	"bytes"
	stdlog "log"
	"strings"
	"testing"
	"time"
)

func TestDebugPrintfHonorsEnabledState(t *testing.T) {
	var output bytes.Buffer
	previous := stdlog.Writer()
	stdlog.SetOutput(&output)
	t.Cleanup(func() {
		DisableDebug()
		stdlog.SetOutput(previous)
	})

	DisableDebug()
	DebugPrintf("hidden %d", 1)
	if output.Len() != 0 {
		t.Fatalf("disabled debug output = %q, want empty", output.String())
	}

	EnableDebug()
	DebugPrintf("visible %d", 2)
	if !strings.Contains(output.String(), "visible 2") {
		t.Fatalf("enabled debug output = %q, want visible message", output.String())
	}
}

func TestGoRecoversAndReportsPanic(t *testing.T) {
	reported := make(chan string, 1)
	SetPanicHandler(func(scope string, recovered any, stack []byte) {
		if scope != "test_scope" || len(stack) == 0 {
			t.Errorf("unexpected panic report scope=%q stack=%d", scope, len(stack))
		}
		reported <- recovered.(string)
	})
	t.Cleanup(func() { SetPanicHandler(nil) })
	Go("test_scope", func() { panic("boom") })
	select {
	case value := <-reported:
		if value != "boom" {
			t.Fatalf("panic value = %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("panic was not reported")
	}
}
