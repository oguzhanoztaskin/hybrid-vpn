//go:build android

package main

import "C"

import (
	"errors"
	"sync"

	// Upstream's opt-in for embedded tsnet on Android: DNS without
	// /etc/resolv.conf and Android's CA store. Its interface fallback stays
	// inert because we register our own getter below.
	_ "tailscale.com/feature/androidbin"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
)

var setupOnce sync.Once

// setupTailscale wires process-wide Tailscale hooks once: every Tailscale
// socket (control, DERP, WireGuard) is protected from our own VPN, and
// interfaces come from Kotlin's view of the physical networks.
func setupTailscale() {
	setupOnce.Do(func() {
		netns.SetAndroidProtectFunc(func(fd int) error {
			if !(jniHost{}).Protect(fd) {
				return errors.New("VpnService.protect failed")
			}
			return nil
		})
		netmon.RegisterInterfaceGetter(jniInterfaces)
	})
}
