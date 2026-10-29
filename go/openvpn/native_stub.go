//go:build !openvpn3

package openvpn

// Available reports whether this build includes OpenVPN 3 Core.
func Available() bool { return false }

// Eval parses a profile without connecting.
func Eval(profile string) (Profile, error) { return Profile{}, ErrUnavailable }

// CheckKeyPassword reports whether password decrypts the profile's inline private key.
func CheckKeyPassword(profile, password string) (bool, error) { return false, ErrUnavailable }

// New prepares a session; Start connects.
func New(cfg Config) (*Client, error) { return nil, ErrUnavailable }
