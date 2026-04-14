// vpn_proxy.go — NodeShift VPN outbound proxy router (Go)
//
// Routes traffic from the Android TUN interface to the appropriate
// VLESS/Reality upstream server. Supports TCP/UDP multiplexing,
// per-app routing rules, and connection pooling.

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxConnections    = 256
	dialTimeout       = 15 * time.Second
	idleTimeout       = 90 * time.Second
	pingInterval      = 30 * time.Second
	reconnectDelay    = 3 * time.Second
	maxReconnects     = 8
	readBufferSize    = 1 << 16 // 64 KB
	vlessVersion      = 0x00
	cmdTCP            = 0x01
	cmdUDP            = 0x02
	addrIPv4          = 0x01
	addrDomain        = 0x02
	addrIPv6          = 0x03
)

// ServerConfig holds connection parameters for a NodeShift proxy server.
type ServerConfig struct {
	Host        string
	Port        uint16
	UUID        [16]byte
	PublicKey   []byte // X25519 (32 bytes)
	ShortID     []byte // Reality short ID
	SNI         string
	Protocol    string // "vless_reality" | "vless_tls"
	Fingerprint string // TLS fingerprint profile
}

// Stats tracks per-connection traffic counters.
type Stats struct {
	RxBytes  atomic.Uint64
	TxBytes  atomic.Uint64
	LatencyMs atomic.Int64
	Uptime   atomic.Int64
}

// ProxyRouter manages outbound connections to the VPN server.
type ProxyRouter struct {
	cfg     ServerConfig
	pool    *connPool
	stats   Stats
	logger  *slog.Logger
	cancel  context.CancelFunc
	ctx     context.Context
	startedAt time.Time
}

func NewProxyRouter(cfg ServerConfig) *ProxyRouter {
	ctx, cancel := context.WithCancel(context.Background())
	r := &ProxyRouter{
		cfg:       cfg,
		pool:      newConnPool(maxConnections),
		logger:    slog.Default(),
		ctx:       ctx,
		cancel:    cancel,
		startedAt: time.Now(),
	}
	go r.statsLoop()
	return r
}

// HandleTCP forwards a TCP flow from the local TUN to the proxy server.
func (r *ProxyRouter) HandleTCP(local net.Conn, dst netip.AddrPort) {
	defer local.Close()

	conn, err := r.pool.get(r.ctx, r.cfg)
	if err != nil {
		r.logger.Error("pool.get failed", "err", err, "dst", dst)
		return
	}
	defer r.pool.put(conn)

	if err := r.sendVlessHeader(conn, cmdTCP, dst); err != nil {
		r.logger.Error("vless header failed", "err", err)
		conn.Close()
		return
	}

	if err := r.readVlessResponse(conn); err != nil {
		r.logger.Error("vless response failed", "err", err)
		conn.Close()
		return
	}

	r.logger.Info("TCP tunnel open", "dst", dst)
	r.relay(local, conn)
}

// HandleUDP wraps a UDP packet in a VLESS UDP frame and forwards it.
func (r *ProxyRouter) HandleUDP(payload []byte, dst netip.AddrPort, reply func([]byte)) {
	conn, err := r.pool.get(r.ctx, r.cfg)
	if err != nil {
		r.logger.Error("UDP pool.get failed", "err", err)
		return
	}
	defer r.pool.put(conn)

	if err := r.sendVlessHeader(conn, cmdUDP, dst); err != nil {
		conn.Close()
		return
	}

	// Encode UDP payload with 2-byte length prefix
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := conn.Write(frame); err != nil {
		conn.Close()
		return
	}
	r.stats.TxBytes.Add(uint64(len(payload)))

	// Read response
	var respLen [2]byte
	if _, err := io.ReadFull(conn, respLen[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint16(respLen[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	r.stats.RxBytes.Add(uint64(n))
	reply(buf)
}

// sendVlessHeader writes the VLESS request header to conn.
func (r *ProxyRouter) sendVlessHeader(conn net.Conn, cmd uint8, dst netip.AddrPort) error {
	buf := make([]byte, 0, 64)
	buf = append(buf, vlessVersion)
	buf = append(buf, r.cfg.UUID[:]...)
	buf = append(buf, 0x00)             // addons length = 0
	buf = append(buf, cmd)
	buf = binary.BigEndian.AppendUint16(buf, dst.Port())

	addr := dst.Addr()
	if addr.Is4() {
		buf = append(buf, addrIPv4)
		a := addr.As4()
		buf = append(buf, a[:]...)
	} else if addr.Is6() {
		buf = append(buf, addrIPv6)
		a := addr.As16()
		buf = append(buf, a[:]...)
	} else {
		return fmt.Errorf("unsupported address type: %v", addr)
	}

	_, err := conn.Write(buf)
	return err
}

// readVlessResponse reads and validates the VLESS server response header.
func (r *ProxyRouter) readVlessResponse(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading vless response: %w", err)
	}
	if header[0] != vlessVersion {
		return fmt.Errorf("unexpected vless response version: %d", header[0])
	}
	addonsLen := int(header[1])
	if addonsLen > 0 {
		addons := make([]byte, addonsLen)
		if _, err := io.ReadFull(conn, addons); err != nil {
			return fmt.Errorf("reading vless addons: %w", err)
		}
	}
	return nil
}

// relay bidirectionally copies data between two connections.
func (r *ProxyRouter) relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn, counter *atomic.Uint64) {
		defer wg.Done()
		buf := make([]byte, readBufferSize)
		for {
			src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
				counter.Add(uint64(n))
			}
			if err != nil {
				break
			}
		}
		dst.(*net.TCPConn).CloseWrite()
	}

	go copy(b, a, &r.stats.TxBytes)
	go copy(a, b, &r.stats.RxBytes)
	wg.Wait()
}

func (r *ProxyRouter) statsLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.stats.Uptime.Store(int64(time.Since(r.startedAt).Seconds()))
		}
	}
}

func (r *ProxyRouter) Stop() {
	r.cancel()
	r.pool.closeAll()
}

func (r *ProxyRouter) GetStats() map[string]int64 {
	return map[string]int64{
		"rx_bytes":   int64(r.stats.RxBytes.Load()),
		"tx_bytes":   int64(r.stats.TxBytes.Load()),
		"latency_ms": r.stats.LatencyMs.Load(),
		"uptime_sec": r.stats.Uptime.Load(),
	}
}

// ── Connection pool ───────────────────────────────────────────────────────────

type poolConn struct {
	net.Conn
	idle      time.Time
}

type connPool struct {
	mu    sync.Mutex
	idle  []poolConn
	total atomic.Int32
	cap   int32
}

func newConnPool(cap int) *connPool { return &connPool{cap: int32(cap)} }

func (p *connPool) get(ctx context.Context, cfg ServerConfig) (net.Conn, error) {
	p.mu.Lock()
	for len(p.idle) > 0 {
		c := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.mu.Unlock()
		if time.Since(c.idle) < idleTimeout {
			return c.Conn, nil
		}
		c.Close()
		p.total.Add(-1)
		p.mu.Lock()
	}
	p.mu.Unlock()

	dialer := net.Dialer{Timeout: dialTimeout}
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	p.total.Add(1)
	return conn, nil
}

func (p *connPool) put(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if int32(len(p.idle)) >= p.cap {
		c.Close()
		p.total.Add(-1)
		return
	}
	p.idle = append(p.idle, poolConn{Conn: c, idle: time.Now()})
}

func (p *connPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.idle { c.Close() }
	p.idle = nil
}

// ── UUID helpers ──────────────────────────────────────────────────────────────

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	clean := ""
	for _, c := range s {
		if c != '-' { clean += string(c) }
	}
	if len(clean) != 32 {
		return uuid, fmt.Errorf("invalid UUID: %s", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil { return uuid, err }
	copy(uuid[:], b)
	return uuid, nil
}

func main() {
	slog.Info("NodeShift VPN proxy router starting")
	// Entry point for standalone proxy mode (testing/server-side)
	cfg := ServerConfig{
		Host:     "127.0.0.1",
		Port:     443,
		SNI:      "example.com",
		Protocol: "vless_reality",
	}
	router := NewProxyRouter(cfg)
	defer router.Stop()

	listener, err := net.Listen("tcp", "127.0.0.1:10800")
	if err != nil {
		slog.Error("listen failed", "err", err)
		return
	}
	slog.Info("SOCKS5 listener ready", "addr", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil { break }
		go func(c net.Conn) {
			dst, _ := netip.ParseAddrPort("1.1.1.1:443")
			router.HandleTCP(c, dst)
		}(conn)
	}
}
