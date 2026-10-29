# ADR 0004: Kotlin/JVM core for M0 and M1

Status: accepted (deviation from the spec's Rust recommendation, scoped to M0/M1)

DNS-only traffic volume is tiny, so a native core buys nothing yet, while a JNI build adds NDK
tooling and a second toolchain to every build. `engine` and `discovery` are pure-JVM Kotlin modules
with no Android imports. They are tested on the host, and the app consumes them directly.

ADR 0003 has since chosen Go for the data plane. The packet path moves to Go. The Kotlin DNS
firewall stays: DNS-level decisions don't touch the per-packet hot path. Policy semantics that Go
must enforce per flow are ported with these tests as the contract.
