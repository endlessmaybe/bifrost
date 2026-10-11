// This file is overlaid into the pinned sing-box source immediately before
// the unified Android libbox build.  It intentionally lives in package
// libbox so sing-box and Xray share one gomobile Go runtime/JNI library.
package libbox

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	xraycore "github.com/xtls/xray-core/core"
	// StartInstance decodes typed configs, but their runtime constructors are
	// registered separately by init(). Embed the pinned upstream distribution
	// so the Android binding has the same handlers and transports as Xray.
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
)

// XraySocketProtector is implemented by the Android platform bridge. Protect
// is called for every Xray upstream socket before connect, preventing the
// transport from being captured again by the owning VpnService TUN.
type XraySocketProtector interface {
	Protect(fd int64) bool
}

var xrayProtectorMu sync.Mutex
var xrayProtector XraySocketProtector
var xrayControllerInstalled bool
var xrayDialerController func(string, string, syscall.RawConn) error

// SetXraySocketProtector installs the process-wide controller used by Xray's
// DefaultSystemDialer. Passing nil removes the callback but leaves the
// controller installed so future connections fail closed rather than silently
// bypassing VpnService.protect.
func SetXraySocketProtector(protector XraySocketProtector) error {
	xrayProtectorMu.Lock()
	defer xrayProtectorMu.Unlock()
	xrayProtector = protector
	if xrayControllerInstalled {
		return nil
	}
	controller := func(_ string, _ string, raw syscall.RawConn) error {
		var protected bool
		err := raw.Control(func(fd uintptr) {
			xrayProtectorMu.Lock()
			p := xrayProtector
			xrayProtectorMu.Unlock()
			protected = p != nil && p.Protect(int64(fd))
			if !protected {
				// Return an error while RawConn still owns the descriptor. The
				// net.Dialer/xray caller closes it exactly once on failure; closing
				// here would race that ownership and can double-close a reused fd.
			}
		})
		if err != nil {
			return err
		}
		if !protected {
			return fmt.Errorf("xray upstream socket was not protected")
		}
		return nil
	}
	if err := internet.RegisterDialerController(controller); err != nil {
		return err
	}
	xrayDialerController = controller
	xrayControllerInstalled = true
	return nil
}

// XrayEngine owns an in-process Xray instance. It does not create files or
// execute a binary from app-private storage.
type XrayEngine struct {
	mu       sync.Mutex
	instance *xraycore.Instance
}

func NewXrayEngine() *XrayEngine { return &XrayEngine{} }

func (e *XrayEngine) Start(configJSON string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.instance != nil {
		return fmt.Errorf("xray engine already running")
	}
	instance, err := xraycore.StartInstance("json", []byte(configJSON))
	if err != nil {
		return err
	}
	e.instance = instance
	return nil
}

func (e *XrayEngine) Stop() error {
	e.mu.Lock()
	instance := e.instance
	e.instance = nil
	e.mu.Unlock()
	if instance == nil {
		return nil
	}
	return instance.Close()
}

func (e *XrayEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.instance != nil
}

// XrayProtectProbe opens only an ephemeral loopback socket and runs the same
// raw-socket controller used by Xray's upstream dialer. It never emits a
// packet, but proves the VpnService.protect callback is actually invoked and
// that an unprotected descriptor is closed before it can connect.
func XrayProtectProbe() bool {
	xrayProtectorMu.Lock()
	controller := xrayDialerController
	protected := xrayProtector != nil
	xrayProtectorMu.Unlock()
	if controller == nil || !protected {
		return false
	}
	// Use an outbound dial, rather than only a ListenConfig callback.  The
	// production failure mode is an upstream Xray socket being captured by the
	// owning TUN; this exercises the exact Dialer.Control path that protects
	// that socket before connect.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer listener.Close()
	accepted := make(chan bool, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- false
			return
		}
		_ = conn.Close()
		accepted <- true
	}()
	dialer := net.Dialer{Control: controller}
	conn, dialErr := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if dialErr == nil {
		_ = conn.Close()
	}
	select {
	case ok := <-accepted:
		return dialErr == nil && ok
	case <-time.After(2 * time.Second):
		return false
	}
}
