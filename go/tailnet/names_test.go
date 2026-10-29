package tailnet

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
)

func addUp(t *testing.T, ctx context.Context, m *Manager, id, url string) *Instance {
	t.Helper()
	inst, err := m.Add(Config{ID: id, StateDir: filepath.Join(t.TempDir(), id), ControlURL: url, Hostname: "phone-" + id, Store: new(mem.Store), Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestMagicDNSNamesArePerTailnet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	personalURL := startTailnet(t, "personal.ts.net")
	workURL := startTailnet(t, "work.ts.net")
	nas := startPeer(t, ctx, personalURL, "nas", "personal")

	m := NewManager()
	t.Cleanup(func() { m.Close() })
	addUp(t, ctx, m, "personal", personalURL)
	work := addUp(t, ctx, m, "work", workURL)

	cases := []struct {
		name, status, tailnet string
	}{
		{"nas.personal.ts.net", NameFound, "personal"},
		{"NAS.Personal.TS.NET.", NameFound, "personal"},
		{"nas.work.ts.net", NameNXDomain, "work"}, // inside work's namespace, no such node: never asked elsewhere
		{"example.com", NameNotTailnet, ""},
		{"personal.ts.net.evil.example", NameNotTailnet, ""},
	}
	for _, c := range cases {
		r := m.Resolve(c.name)
		if r.Status != c.status || r.Tailnet != c.tailnet {
			t.Errorf("%s: got %+v, want %s in %q", c.name, r, c.status, c.tailnet)
		}
	}
	if r := m.Resolve("nas.personal.ts.net"); len(r.Addrs) == 0 || r.Addrs[0] != nas {
		t.Errorf("nas resolved to %v, want %v", r.Addrs, nas)
	}

	// A peer joining later becomes resolvable and routable via the IPN bus watcher.
	late := startPeer(t, ctx, workURL, "late", "work")
	deadline := time.Now().Add(20 * time.Second)
	for m.Resolve("late.work.ts.net").Status != NameFound && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if r := m.Resolve("late.work.ts.net"); r.Status != NameFound || r.Addrs[0] != late {
		t.Fatalf("late peer: %+v", r)
	}
	if ok, _ := work.Owns(ctx, late); !ok {
		t.Error("late peer address not owned after refresh")
	}

	// Two tailnets claiming the same suffix: refuse to guess.
	addUp(t, ctx, m, "work2", startTailnet(t, "work.ts.net"))
	if r := m.Resolve("late.work.ts.net"); r.Status != NameAmbiguous || len(r.Claimants) != 2 {
		t.Errorf("shared suffix: got %+v, want ambiguous with 2 claimants", r)
	}
}

// TestSnapshotSeesPeersPresentBeforeStart uses Start (as the Android engine
// does), so the snapshot comes only from the IPN bus watcher.
func TestSnapshotSeesPeersPresentBeforeStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	url := startTailnet(t, "early.ts.net")
	peer := startPeer(t, ctx, url, "early", "x")
	m := NewManager()
	t.Cleanup(func() { m.Close() })
	inst, err := m.Add(Config{ID: "e", StateDir: filepath.Join(t.TempDir(), "e"), ControlURL: url, Hostname: "phone", Store: new(mem.Store), Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for m.Resolve("early.early.ts.net").Status != NameFound && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if r := m.Resolve("early.early.ts.net"); r.Status != NameFound || r.Addrs[0] != peer {
		s := inst.Summary(ctx)
		t.Fatalf("pre-existing peer not in snapshot: %+v (node state %s, %d peers in status)", r, s.State, s.Peers)
	}
}

func TestPeersListsMachinesWithDetails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	url := startTailnet(t, "home.ts.net")
	nas := startPeer(t, ctx, url, "nas", "home")
	m := NewManager()
	t.Cleanup(func() { m.Close() })
	inst := addUp(t, ctx, m, "home", url)
	peers, err := inst.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || !peers[0].Self || peers[0].HostName != "phone-home" {
		t.Fatalf("peers: %+v", peers)
	}
	p := peers[1]
	if p.HostName != "nas" || p.DNSName != "nas.home.ts.net" || len(p.IPs) != 2 || p.IPs[0] != nas.String() || p.ID == "" || p.OS == "" {
		t.Errorf("peer details: %+v", p)
	}
}
