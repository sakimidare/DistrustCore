package log

import (
	"encoding/hex"
	"io"
	"log"
	"os"
	runtimeDebug "runtime/debug"
	"sync"
	"sync/atomic"
)

var debug atomic.Bool
var panicHandler struct {
	sync.RWMutex
	handler func(string, any, []byte)
}

func SetPanicHandler(handler func(scope string, recovered any, stack []byte)) {
	panicHandler.Lock()
	panicHandler.handler = handler
	panicHandler.Unlock()
}

// Go starts a guarded background task. Panics are logged with a full Go stack
// and forwarded to the embedded host instead of terminating the process.
func Go(scope string, task func()) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				stack := runtimeDebug.Stack()
				Printf("background panic scope=%s: %v\n%s", scope, recovered, stack)
				panicHandler.RLock()
				handler := panicHandler.handler
				panicHandler.RUnlock()
				if handler != nil {
					func() {
						defer func() { _ = recover() }()
						handler(scope, recovered, stack)
					}()
				}
			}
		}()
		task()
	}()
}

func Init() {
	log.SetOutput(os.Stdout)
}

// SetOutput redirects all core logs. Mobile hosts use this to mirror Go logs
// into their native logging and UI pipeline.
func SetOutput(writer io.Writer) {
	if writer == nil {
		log.SetOutput(os.Stdout)
		return
	}
	log.SetOutput(writer)
}

func EnableDebug() {
	debug.Store(true)
}

func DisableDebug() {
	debug.Store(false)
}

func DebugEnabled() bool {
	return debug.Load()
}

func Print(v ...any) {
	log.Print(v...)
}

func DebugPrint(v ...any) {
	if debug.Load() {
		log.Print(v...)
	}
}

func Println(v ...any) {
	log.Println(v...)
}

func DebugPrintln(v ...any) {
	if debug.Load() {
		log.Println(v...)
	}
}

func Printf(format string, v ...any) {
	log.Printf(format, v...)
}

func DebugPrintf(format string, v ...any) {
	if debug.Load() {
		log.Printf(format, v...)
	}
}

func Fatal(v ...any) {
	log.Fatal(v...)
}

func Fatalf(format string, v ...any) {
	log.Fatalf(format, v...)
}

func DumpHex(buf []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer func(stdoutDumper io.WriteCloser) {
		_ = stdoutDumper.Close()
	}(stdoutDumper)
	_, _ = stdoutDumper.Write(buf)
}

func DebugDumpHex(buf []byte) {
	if debug.Load() {
		stdoutDumper := hex.Dumper(os.Stdout)
		defer func(stdoutDumper io.WriteCloser) {
			_ = stdoutDumper.Close()
		}(stdoutDumper)
		_, _ = stdoutDumper.Write(buf)
	}
}

func NewLogger(prefix string) *log.Logger {
	return log.New(os.Stdout, prefix, log.LstdFlags)
}
