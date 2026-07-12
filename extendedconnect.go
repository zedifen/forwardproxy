package forwardproxy

import (
	"sync"
	_ "unsafe"
)

// x/net/http2 currently has no public server option for Extended CONNECT.
// Its package-level gate is initialized from GODEBUG=http2xconnect=1 and is
// consulted both when writing SETTINGS_ENABLE_CONNECT_PROTOCOL and when
// validating the :protocol pseudo-header. Link to the gate so the forward
// proxy can support Extended CONNECT without requiring a process-wide
// environment variable.
//
//go:linkname http2DisableExtendedConnectProtocol golang.org/x/net/http2.disableExtendedConnectProtocol
var http2DisableExtendedConnectProtocol bool

var hiddenExtendedConnectSettings struct {
	sync.Mutex
	handlers int
}

func init() {
	setHTTP2ExtendedConnectEnabled(true)
}

func setHTTP2ExtendedConnectEnabled(enabled bool) {
	http2DisableExtendedConnectProtocol = !enabled
}

func (h *Handler) registerHiddenExtendedConnectSetting() {
	if !h.HideExtendedConnectSetting || h.hideExtendedConnectSettingRegistered {
		return
	}

	hiddenExtendedConnectSettings.Lock()
	defer hiddenExtendedConnectSettings.Unlock()
	hiddenExtendedConnectSettings.handlers++
	h.hideExtendedConnectSettingRegistered = true
	setHTTP2ExtendedConnectEnabled(false)
}

func (h *Handler) unregisterHiddenExtendedConnectSetting() {
	if !h.hideExtendedConnectSettingRegistered {
		return
	}

	hiddenExtendedConnectSettings.Lock()
	defer hiddenExtendedConnectSettings.Unlock()
	hiddenExtendedConnectSettings.handlers--
	h.hideExtendedConnectSettingRegistered = false
	if hiddenExtendedConnectSettings.handlers == 0 {
		setHTTP2ExtendedConnectEnabled(true)
	}
}
