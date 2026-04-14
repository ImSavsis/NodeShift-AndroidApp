// vpn_routing.go — IP routing table and split-tunnel logic for NodeShift VPN

package main

import (
	"net/netip"
	"sort"
	"sync"
)

// RoutingPolicy decides whether a destination should go through the VPN tunnel
// or be sent directly via the physical network interface.
type RoutingPolicy uint8

const (
	PolicyTunnel RoutingPolicy = iota // Route through VPN
	PolicyDirect                      // Bypass VPN (split tunnel)
	PolicyBlock                       // Drop packets
)

type RouteEntry struct {
	Prefix netip.Prefix
	Policy RoutingPolicy
	AppUID int // -1 = all apps, ≥0 = specific Android app UID
}

// RoutingTable implements a longest-prefix-match routing table.
type RoutingTable struct {
	mu      sync.RWMutex
	routes  []RouteEntry // sorted by prefix length descending
	appRules map[int]RoutingPolicy
}

func NewRoutingTable() *RoutingTable {
	rt := &RoutingTable{appRules: make(map[int]RoutingPolicy)}
	// RFC 1918 private ranges bypass VPN by default
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("10.0.0.0/8"),      Policy: PolicyDirect, AppUID: -1})
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("172.16.0.0/12"),   Policy: PolicyDirect, AppUID: -1})
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("192.168.0.0/16"),  Policy: PolicyDirect, AppUID: -1})
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("127.0.0.0/8"),     Policy: PolicyDirect, AppUID: -1})
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("169.254.0.0/16"),  Policy: PolicyDirect, AppUID: -1})
	// Default: tunnel everything else
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("0.0.0.0/0"),       Policy: PolicyTunnel, AppUID: -1})
	rt.AddRoute(RouteEntry{Prefix: netip.MustParsePrefix("::/0"),             Policy: PolicyTunnel, AppUID: -1})
	return rt
}

func (rt *RoutingTable) AddRoute(e RouteEntry) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes = append(rt.routes, e)
	sort.Slice(rt.routes, func(i, j int) bool {
		bi, bj := rt.routes[i].Prefix.Bits(), rt.routes[j].Prefix.Bits()
		return bi > bj // longer prefix = higher priority
	})
}

func (rt *RoutingTable) RemoveRoute(prefix netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	filtered := rt.routes[:0]
	for _, r := range rt.routes {
		if r.Prefix != prefix { filtered = append(filtered, r) }
	}
	rt.routes = filtered
}

func (rt *RoutingTable) Lookup(addr netip.Addr, appUID int) RoutingPolicy {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// App-specific rule takes priority
	if appUID >= 0 {
		if policy, ok := rt.appRules[appUID]; ok {
			return policy
		}
	}

	// Longest prefix match
	for _, r := range rt.routes {
		if r.AppUID >= 0 && r.AppUID != appUID { continue }
		if r.Prefix.Contains(addr) { return r.Policy }
	}
	return PolicyTunnel
}

func (rt *RoutingTable) SetAppPolicy(appUID int, policy RoutingPolicy) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.appRules[appUID] = policy
}

func (rt *RoutingTable) ClearAppPolicy(appUID int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.appRules, appUID)
}

// DNSRouter handles DNS request interception and rewriting for the VPN.
type DNSRouter struct {
	mu       sync.RWMutex
	cache    map[string][]netip.Addr
	fakeDNS  map[netip.Addr]string  // fake IP → real domain (for FQDN routing)
	upstream []string               // upstream DNS servers
	nextFake netip.Addr
}

func NewDNSRouter(upstream []string) *DNSRouter {
	return &DNSRouter{
		cache:    make(map[string][]netip.Addr),
		fakeDNS:  make(map[netip.Addr]string),
		upstream: upstream,
		nextFake: netip.MustParseAddr("198.18.0.1"), // RFC 2544 test range
	}
}

func (d *DNSRouter) AllocateFakeIP(domain string) netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	for addr, dom := range d.fakeDNS {
		if dom == domain { return addr }
	}
	fake := d.nextFake
	d.fakeDNS[fake] = domain
	// Increment
	a := fake.As4()
	for i := 3; i >= 0; i-- {
		a[i]++
		if a[i] != 0 { break }
	}
	d.nextFake = netip.AddrFrom4(a)
	return fake
}

func (d *DNSRouter) ResolveFake(ip netip.Addr) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	dom, ok := d.fakeDNS[ip]
	return dom, ok
}
