package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogSignalsOnlyWhenAlive(t *testing.T) {
	var sent atomic.Int64
	var hung atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := func(c context.Context) bool {
		if hung.Load() {
			<-c.Done() // «завислий» сервіс
			return false
		}
		return true
	}
	go runWatchdog(ctx, 150*time.Millisecond, probe, func(s string) bool {
		if s == "WATCHDOG=1" {
			sent.Add(1)
		}
		return true
	})
	deadline := time.Now().Add(5 * time.Second)
	for sent.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	hung.Store(true)
	time.Sleep(100 * time.Millisecond)
	n := sent.Load()
	time.Sleep(400 * time.Millisecond)
	if sent.Load() != n {
		t.Fatalf("watchdog kept pinging while hung: %d → %d", n, sent.Load())
	}
	hung.Store(false)
	for d := time.Now().Add(5 * time.Second); sent.Load() <= n && time.Now().Before(d); {
		time.Sleep(10 * time.Millisecond)
	}
	if sent.Load() <= n {
		t.Fatal("pings did not resume")
	}
}

func TestSdNotifyAndInterval(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "notify")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	if !sdNotify("READY=1") {
		t.Fatal("notify failed")
	}
	buf := make([]byte, 64)
	ln.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := ln.Read(buf)
	if string(buf[:n]) != "READY=1" {
		t.Fatalf("got %q", buf[:n])
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if sdNotify("READY=1") {
		t.Fatal("must be a no-op without systemd")
	}
	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", "")
	if watchdogInterval() != 30*time.Second {
		t.Fatal("interval")
	}
	t.Setenv("WATCHDOG_PID", "1")
	if os.Getpid() != 1 && watchdogInterval() != 0 {
		t.Fatal("watchdog for another pid must be ignored")
	}
	_ = strings.TrimSpace
}
