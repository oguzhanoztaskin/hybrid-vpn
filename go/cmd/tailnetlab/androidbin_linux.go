//go:build linux

package main

// Peer mode runs as a raw binary under adb on Android: interfaces, DNS and CA
// roots need upstream's Android fallbacks.
import _ "tailscale.com/feature/androidbin"
