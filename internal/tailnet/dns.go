package tailnet

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// HostSource returns the proxy hostnames that are allowed to resolve to the
// tailnet address. It is called per query so newly added sites resolve without
// a restart.
type HostSource func() ([]string, error)

// DNS is a deliberately small authoritative responder for Tailscale split DNS.
// It answers A queries for configured proxy hostnames only; it never recurses.
type DNS struct {
	addr  string
	ip    net.IP
	hosts HostSource
	log   *slog.Logger
	soa   dns.RR

	mu      sync.Mutex
	udp     *dns.Server
	tcp     *dns.Server
	udpAddr string
	tcpAddr string
	err     error
	closed  bool
}

// NewDNS creates a responder. addr must already be a tailnet address and port
// (normally 100.x.y.z:53).
func NewDNS(addr string, hosts HostSource, log *slog.Logger) *DNS {
	host, _, _ := net.SplitHostPort(addr)
	d := &DNS{addr: addr, ip: net.ParseIP(host).To4(), hosts: hosts, log: log}
	if rr, err := dns.NewRR("wafproxy.local. 60 IN SOA ns.wafproxy.local. hostmaster.wafproxy.local. 1 3600 600 86400 60"); err == nil {
		d.soa = rr
	}
	return d
}

// Start binds UDP and TCP on the configured address. It returns as soon as both
// sockets are bound; serving continues in the background.
func (d *DNS) Start() error {
	pc, err := net.ListenPacket("udp", d.addr)
	if err != nil {
		return fmt.Errorf("listen DNS UDP %s: %w", d.addr, err)
	}
	ln, err := net.Listen("tcp", d.addr)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("listen DNS TCP %s: %w", d.addr, err)
	}

	d.mu.Lock()
	d.udpAddr = pc.LocalAddr().String()
	d.tcpAddr = ln.Addr().String()
	d.udp = &dns.Server{PacketConn: pc, Handler: d}
	d.tcp = &dns.Server{Listener: ln, Handler: d}
	udpSrv, tcpSrv := d.udp, d.tcp
	d.mu.Unlock()

	go d.serve("udp", udpSrv)
	go d.serve("tcp", tcpSrv)
	if d.log != nil {
		d.log.Info("tailnet split DNS listening", "udp", d.udpAddr, "tcp", d.tcpAddr)
	}
	return nil
}

func (d *DNS) serve(network string, srv *dns.Server) {
	err := srv.ActivateAndServe()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil && !d.closed {
		d.err = err
	}
	if d.log != nil && err != nil && !d.closed {
		d.log.Warn("tailnet DNS listener stopped", "network", network, "err", err)
	}
}

// ServeDNS implements dns.Handler.
func (d *DNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	// This is an IPv4-only ingress path. An empty AAAA answer lets clients fall
	// back to A without treating the name as nonexistent.
	if q.Qtype != dns.TypeA {
		m.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(m)
		return
	}
	hosts, err := d.hosts()
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	name := normalizeName(q.Name)
	if d.ip == nil {
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	for _, host := range hosts {
		if normalizeName(host) != name {
			continue
		}
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   d.ip,
		}}
		_ = w.WriteMsg(m)
		return
	}
	m.Rcode = dns.RcodeNameError
	if d.soa != nil {
		m.Ns = []dns.RR{d.soa}
	}
	_ = w.WriteMsg(m)
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// UDPAddr and TCPAddr expose the bound addresses for tests and status.
func (d *DNS) UDPAddr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.udpAddr
}

func (d *DNS) TCPAddr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tcpAddr
}

// Err returns the first serve error, if any.
func (d *DNS) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// Close stops both listeners.
func (d *DNS) Close() {
	d.mu.Lock()
	d.closed = true
	udp, tcp := d.udp, d.tcp
	d.mu.Unlock()
	if udp != nil {
		_ = udp.Shutdown()
	}
	if tcp != nil {
		_ = tcp.Shutdown()
	}
}
