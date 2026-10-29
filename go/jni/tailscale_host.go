//go:build jnihost && !android

package main

// setupTailscale is a no-op in host builds of the JNI glue (no VpnService).
func setupTailscale() {}
