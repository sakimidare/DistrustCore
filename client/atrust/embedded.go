package atrust

import (
	"fmt"
	"sync"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/log"
)

var embeddedState struct {
	sync.RWMutex
	enabled bool
	handler func(error)
}

// SetEmbeddedMode prevents session-expiry paths from terminating the Android
// process and reports them to the mobile host instead.
func SetEmbeddedMode(handler func(error)) {
	embeddedState.Lock()
	embeddedState.enabled = true
	embeddedState.handler = handler
	embeddedState.Unlock()
}

func sessionInvalidError(scope string, code int64, message string) error {
	return fmt.Errorf("%s: aTrust session is invalid (code %d): %s: %w", scope, code, message, auth.ErrSessionInvalid)
}

func handleSessionInvalid(err error) bool {
	embeddedState.RLock()
	enabled := embeddedState.enabled
	handler := embeddedState.handler
	embeddedState.RUnlock()
	if !enabled {
		log.Fatalf("%v", err)
		return false
	}
	log.Printf("embedded session expired: %v", err)
	if handler != nil {
		handler(err)
	}
	return true
}
