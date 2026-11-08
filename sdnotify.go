package main

import (
	"context"
	"net"
	"os"
	"strconv"
	"time"
)

// Сповіщення systemd (sd_notify) без залежностей: READY=1 після старту і WATCHDOG=1, доки
// служба справді відповідає. Якщо процес не впав, а завис (наприклад, заблокувався), systemd
// перестане отримувати WATCHDOG і перезапустить службу (WatchdogSec у unit).

func sdNotify(state string) bool {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return false
	}
	if sock[0] == '@' { // абстрактний сокет
		sock = "\x00" + sock[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write([]byte(state))
	return err == nil
}

// watchdogInterval — з WATCHDOG_USEC (і WATCHDOG_PID, якщо задано); 0 — сторожа немає.
func watchdogInterval() time.Duration {
	us, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || us <= 0 {
		return 0
	}
	if p := os.Getenv("WATCHDOG_PID"); p != "" && p != strconv.Itoa(os.Getpid()) {
		return 0
	}
	return time.Duration(us) * time.Microsecond
}

// runWatchdog — раз на третину інтервалу перевіряє probe (з тайм-аутом) і, якщо служба жива,
// шле WATCHDOG=1. Завислий probe — сигналу немає, systemd перезапустить службу.
func runWatchdog(ctx context.Context, interval time.Duration, probe func(context.Context) bool, notify func(string) bool) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, interval/3)
		ok := make(chan bool, 1)
		go func() { ok <- probe(pctx) }()
		select {
		case v := <-ok:
			if v {
				notify("WATCHDOG=1")
			}
		case <-pctx.Done():
			logf("watchdog: service did not answer within %s", interval/3)
		}
		cancel()
	}
}
