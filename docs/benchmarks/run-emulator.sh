#!/usr/bin/env bash
# Reproducible engine benchmark on an Android emulator. Methodology: docs/benchmarks/README.md.
#
#   docs/benchmarks/run-emulator.sh <results-dir> [off] [dns] [go]
#
# Prerequisites:
#   - debug build installed, VPN consent pre-granted:  adb shell appops set com.oguzhanstech.hybridvpn ACTIVATE_VPN allow
#   - hvbench (linux/arm64, static) pushed to /data/local/tmp/hvbench
#   - hvbench server running on the host:               hvbench server -listen 127.0.0.1:5201
#     (the emulator reaches host loopback as 10.0.2.2)
set -uo pipefail

SERIAL=${SERIAL:-emulator-5554}
ADB=${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}
PKG=com.oguzhanstech.hybridvpn
BENCH=/data/local/tmp/hvbench
SERVER=${SERVER:-10.0.2.2:5201}
RUNS=${RUNS:-3}
IDLE=${IDLE_SECONDS:-300}
# SKIP_IDLE=1 / SKIP_TRANSITION=1 leave out those phases (on a phone the idle phase locks the screen,
# and the transition test turns Wi-Fi off).
SKIP_IDLE=${SKIP_IDLE:-0}
SKIP_TRANSITION=${SKIP_TRANSITION:-0}
OUT=${1:?usage: run-emulator.sh <results-dir> [off] [dns] [go]}
shift
MODES=${*:-off dns go}
mkdir -p "$OUT"

a() { "$ADB" -s "$SERIAL" "$@"; }
log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

ui_dump() { a shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; a shell cat /sdcard/ui.xml; }
screen_has() { ui_dump | grep -q "text=\"$1\""; }
tap_text() {
	local xy
	xy=$(ui_dump | python3 -c '
import re, sys
t = sys.argv[1]
for node in re.findall(r"<node [^>]*>", sys.stdin.read()):
    if ("text=\"%s\"" % t) in node:
        a = list(map(int, re.search(r"bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", node).groups()))
        print((a[0] + a[2]) // 2, (a[1] + a[3]) // 2)
        break' "$1")
	[ -n "$xy" ] && a shell input tap $xy
}
dismiss_anr() { screen_has "Wait" && tap_text "Wait" && sleep 2; return 0; }
wake() { a shell input keyevent KEYCODE_WAKEUP; a shell wm dismiss-keyguard >/dev/null 2>&1; sleep 1; }

open_status() {
	a shell am start -n $PKG/.MainActivity >/dev/null 2>&1
	sleep 3
	dismiss_anr
	tap_text Status
	sleep 1
	for _ in 1 2 3; do a shell input swipe 540 500 540 1800 150; done
}

stop_vpn() {
	open_status
	screen_has Stop && tap_text Stop && sleep 3
	return 0
}

# Engine (FULL_TUNNEL or DNS_ONLY, key "engine") and resolver are written to the app's preferences
# while it is stopped.
configure() {
	a shell am force-stop $PKG
	a shell "run-as $PKG sed -i -e '/<string name=\"engine\">/d' -e 's#</map>#    <string name=\"engine\">$1</string>\n</map>#' -e 's#<string name=\"upstreamMode\">[A-Z]*</string>#<string name=\"upstreamMode\">NETWORK</string>#' shared_prefs/settings.xml"
}

start_vpn() {
	open_status
	tap_text Start
	for _ in $(seq 1 30); do
		screen_has "Protection on" && return 0
		sleep 1
	done
	log "VPN did not start"
	return 1
}

bench() { a shell $BENCH "$@" -label "$MODE" | tr -d '\r' >>"$OUT/$MODE.jsonl"; }

# System-wide busy time (/proc/stat, all CPUs, minus idle and iowait) and the app's CPU time
# (utime+stime), in ticks of 10 ms; the app's part reads 0 when it isn't running.
cpu_snap() {
	local pid
	pid=$(a shell pidof $PKG | tr -d '\r')
	{ a shell head -1 /proc/stat; [ -n "$pid" ] && a shell run-as $PKG cat /proc/$pid/stat; } | tr -d '\r' | python3 -c '
import sys
lines = sys.stdin.read().splitlines()
c = list(map(int, lines[0].split()[1:]))
busy = sum(c) - c[3] - c[4]
app = 0
if len(lines) > 1 and ")" in lines[1]:
    f = lines[1].rsplit(")", 1)[1].split()
    app = int(f[11]) + int(f[12])
print(busy, app)'
}

# A bench run with the CPU it cost: the app's and the whole system's (kernel networking, the
# hvbench client and everything else), so engines can be compared per transferred byte.
bench_cpu() {
	local b1 b2 t1 t2
	b1=$(cpu_snap)
	t1=$(now_ms)
	bench "$@"
	t2=$(now_ms)
	b2=$(cpu_snap)
	python3 -c '
import json, sys
(s1, a1), (s2, a2) = map(int, sys.argv[1].split()), map(int, sys.argv[2].split())
print(json.dumps({"mode": "cpu", "label": sys.argv[5], "bench": sys.argv[6], "wall_ms": int(sys.argv[4]) - int(sys.argv[3]),
    "app_cpu_ms": (a2 - a1) * 10, "system_busy_ms": (s2 - s1) * 10}))' "$b1" "$b2" "$t1" "$t2" "$MODE" "$1" >>"$OUT/$MODE.jsonl"
}

# CPU ticks (utime+stime, USER_HZ=100) and context switches summed over all threads.
proc_sample() {
	local pid=$1
	a shell run-as $PKG sh -c "'cat /proc/$pid/stat; cat /proc/$pid/task/*/status'" | tr -d '\r' | python3 -c '
import sys, json
lines = sys.stdin.read().splitlines()
f = lines[0].rsplit(")", 1)[1].split()
ticks = int(f[11]) + int(f[12])   # utime, stime
vol = sum(int(l.split()[1]) for l in lines if l.startswith("voluntary_ctxt_switches"))
inv = sum(int(l.split()[1]) for l in lines if l.startswith("nonvoluntary_ctxt_switches"))
threads = sum(1 for l in lines if l.startswith("Name:"))
print(json.dumps({"ticks": ticks, "vol": vol, "invol": inv, "threads": threads}))'
}

idle_test() {
	local pid s1 s2 t1 t2
	a shell input keyevent KEYCODE_HOME
	a shell input keyevent KEYCODE_SLEEP
	sleep 60
	pid=$(a shell pidof $PKG | tr -d '\r')
	t1=$(now_ms)
	s1=$(proc_sample "$pid")
	sleep "$IDLE"
	s2=$(proc_sample "$pid")
	t2=$(now_ms)
	wake
	python3 -c '
import json, sys
s1, s2 = json.loads(sys.argv[1]), json.loads(sys.argv[2])
mins = (int(sys.argv[4]) - int(sys.argv[3])) / 60000
print(json.dumps({"mode": "idle", "label": sys.argv[5], "minutes": round(mins, 2),
    "cpu_ms_per_min": round((s2["ticks"] - s1["ticks"]) * 10 / mins, 1),
    "voluntary_switches_per_min": round((s2["vol"] - s1["vol"]) / mins, 1),
    "involuntary_switches_per_min": round((s2["invol"] - s1["invol"]) / mins, 1),
    "threads": s2["threads"]}))' "$s1" "$s2" "$t1" "$t2" "$MODE" >>"$OUT/$MODE.jsonl"
	a shell dumpsys meminfo $PKG >"$OUT/$MODE-meminfo-idle.txt"
}

connect_ok() { a shell $BENCH connect -server "$SERVER" -n 1 | grep -q '"ok":1'; }
dns_ok() { a shell $BENCH dns -server "$RESOLVER" -name "example.org" -n 1 | grep -q '"ok":1'; }

tun_up() { a shell ip addr show tun0 >/dev/null 2>&1 && echo true || echo false; }

# Wi-Fi off/on with a 1 GB transfer in flight: does the flow complete, and how
# long until new connections and DNS work again?
transition_test() {
	local t0 tconn tdns
	a shell "rm -f /data/local/tmp/bg.json; nohup $BENCH tcp-down -server $SERVER -bytes 1073741824 -label bg >/data/local/tmp/bg.json 2>&1 &"
	sleep 5
	t0=$(now_ms)
	a shell svc wifi disable
	tconn=-1
	for _ in $(seq 1 60); do connect_ok && { tconn=$(($(now_ms) - t0)); break; }; sleep 0.2; done
	tdns=-1
	for _ in $(seq 1 60); do dns_ok && { tdns=$(($(now_ms) - t0)); break; }; sleep 0.2; done
	local vpn_during
	vpn_during=$(tun_up)
	a shell svc wifi enable
	sleep 15
	local back=-1 t1
	t1=$(now_ms)
	for _ in $(seq 1 60); do connect_ok && { back=$(($(now_ms) - t1)); break; }; sleep 0.2; done
	# Let the bulk transfer finish (or fail) and record what it reported.
	for _ in $(seq 1 120); do a shell "pgrep -f 'hvbench tcp-down' >/dev/null" || break; sleep 1; done
	a shell "pkill -f 'hvbench tcp-down'"
	local bulk
	bulk=$(a shell cat /data/local/tmp/bg.json | tr -d '\r\n')
	[ -z "$bulk" ] && bulk='{"error":"still running after 120s (stalled)"}'
	local vpn=n/a
	[ "$MODE" != off ] && vpn=$(tun_up)
	echo "{\"mode\":\"transition\",\"label\":\"$MODE\",\"wifi_off_to_connect_ms\":$tconn,\"wifi_off_to_dns_ms\":$tdns,\"after_wifi_on_connect_ms\":$back,\"tun_up_on_cellular\":\"${vpn_during}\",\"tun_up_after\":\"$vpn\",\"bulk_flow\":$bulk}" >>"$OUT/$MODE.jsonl"
}

# Keep the screen on between phases (the idle phase turns it off explicitly); restore on exit.
OLD_TIMEOUT=$(a shell settings get system screen_off_timeout | tr -d '\r')
a shell settings put system screen_off_timeout 1800000
trap 'a shell settings put system screen_off_timeout "$OLD_TIMEOUT"' EXIT
wake

for MODE in $MODES; do
	log "=== $MODE"
	stop_vpn
	case $MODE in
	off) configure DNS_ONLY; open_status; RESOLVER=${NETWORK_RESOLVER:-10.0.2.3:53} ;;
	dns) configure DNS_ONLY; start_vpn || continue; RESOLVER=10.215.173.2:53 ;;
	go) configure FULL_TUNNEL; start_vpn || continue; RESOLVER=10.215.173.2:53 ;;
	esac
	echo "{\"mode\":\"setup\",\"label\":\"$MODE\",\"tun_up\":$(tun_up)}" >>"$OUT/$MODE.jsonl"
	sleep 10
	a shell dumpsys meminfo $PKG >"$OUT/$MODE-meminfo-start.txt"

	log "dns"
	a shell $BENCH dns -server "$RESOLVER" -name example.org -n 5 >/dev/null # warm the cache
	bench dns -server "$RESOLVER" -name example.org -n 200
	bench dns -server "$RESOLVER" -name example.net -n 50 -uncached
	log "latency"
	bench connect -server "$SERVER" -n 40
	bench rtt -server "$SERVER" -n 200
	for r in $(seq 1 "$RUNS"); do
		log "throughput run $r"
		bench_cpu tcp-down -server "$SERVER" -bytes 134217728
		bench_cpu tcp-up -server "$SERVER" -bytes 134217728
		bench_cpu udp -server "$SERVER" -n 20000 -size 1200
	done
	a shell dumpsys meminfo $PKG >"$OUT/$MODE-meminfo-load.txt"

	if [ "$SKIP_IDLE" != 1 ]; then log "idle ${IDLE}s"; idle_test; fi
	if [ "$SKIP_TRANSITION" != 1 ]; then log "transition"; transition_test; fi
	[ "$MODE" != off ] && stop_vpn
done
log "done: $OUT"
