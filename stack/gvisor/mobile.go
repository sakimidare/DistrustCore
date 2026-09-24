package gvisor

import "sync"

// Mobile hosts embed this stack inside an application process that also owns the
// user interface. A fatal stack error must therefore be reported to the caller
// instead of panicking or calling os.Exit, both of which would tear down the
// whole Android process and look like an application crash to the user.
var mobileState struct {
	mu      sync.RWMutex
	enabled bool
	handler func(error)
}

// SetMobileMode switches the stack into non-terminating error handling. The
// handler receives every fatal stack error and runs on the stack's goroutine, so
// implementations must not block.
func SetMobileMode(handler func(error)) {
	mobileState.mu.Lock()
	defer mobileState.mu.Unlock()
	mobileState.enabled = true
	mobileState.handler = handler
}

// IsMobileMode reports whether the stack runs in an embedded mobile host.
func IsMobileMode() bool {
	mobileState.mu.RLock()
	defer mobileState.mu.RUnlock()
	return mobileState.enabled
}

// mobileFatal reports the error and returns true when mobile mode handled it.
func mobileFatal(err error) bool {
	mobileState.mu.RLock()
	enabled := mobileState.enabled
	handler := mobileState.handler
	mobileState.mu.RUnlock()
	if !enabled {
		return false
	}
	if handler != nil {
		handler(err)
	}
	return true
}
