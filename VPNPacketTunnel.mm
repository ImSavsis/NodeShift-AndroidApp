// VPNPacketTunnel.mm — NodeShift VPN iOS Network Extension
//
// Implements NEPacketTunnelProvider for iOS 16+. Handles tunnel lifecycle,
// packet forwarding between the TUN interface and the VLESS/Reality proxy,
// and reconnection logic.
//
// Add to Info.plist: NSExtension → NEVPNDivert → PacketTunnel

#import <NetworkExtension/NetworkExtension.h>
#import <Foundation/Foundation.h>
#import <os/log.h>
#import "VPNPacketTunnel.h"
#import "CryptoHelper.h"
#import "ProtocolHandler.h"
#import "NetworkMonitor.h"

static os_log_t kLog = nil;
#define LOG(fmt, ...) os_log_with_type(kLog, OS_LOG_TYPE_INFO, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) os_log_with_type(kLog, OS_LOG_TYPE_ERROR, fmt, ##__VA_ARGS__)

static const NSTimeInterval kReconnectDelay     = 3.0;
static const NSInteger       kMaxReconnectCount  = 8;
static const NSInteger       kStatsIntervalSec   = 2;
static const uint32_t        kTunnelMTU          = 1380;

@interface VPNPacketTunnel () <ProtocolHandlerDelegate, NetworkMonitorDelegate>

@property (nonatomic, strong) ProtocolHandler    *protocolHandler;
@property (nonatomic, strong) NetworkMonitor     *netMonitor;
@property (nonatomic, strong) NSTimer            *statsTimer;
@property (nonatomic, strong) dispatch_queue_t    ioQueue;
@property (nonatomic, strong) dispatch_queue_t    controlQueue;

@property (nonatomic, assign) NSInteger   reconnectCount;
@property (nonatomic, assign) BOOL        intentionalStop;
@property (nonatomic, assign) uint64_t    totalRxBytes;
@property (nonatomic, assign) uint64_t    totalTxBytes;
@property (nonatomic, assign) NSTimeInterval tunnelStartTime;

@property (nonatomic, copy) void (^startCompletion)(NSError * _Nullable);

@end

@implementation VPNPacketTunnel

+ (void)initialize {
    if (self == [VPNPacketTunnel class]) {
        kLog = os_log_create("space.nodeshift.vpn.extension", "PacketTunnel");
    }
}

- (instancetype)init {
    if (self = [super init]) {
        _ioQueue      = dispatch_queue_create("nodeshift.vpn.io",
                            dispatch_queue_attr_make_with_qos_class(
                                DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));
        _controlQueue = dispatch_queue_create("nodeshift.vpn.ctrl",
                            dispatch_queue_attr_make_with_qos_class(
                                DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0));
        _reconnectCount    = 0;
        _intentionalStop   = NO;
        _totalRxBytes      = 0;
        _totalTxBytes      = 0;
    }
    return self;
}

// ── NEPacketTunnelProvider lifecycle ─────────────────────────────────────────

- (void)startTunnelWithOptions:(NSDictionary<NSString *, NSObject *> *)options
             completionHandler:(void (^)(NSError *))completionHandler {
    LOG("startTunnel called");
    self.intentionalStop = NO;
    self.startCompletion = completionHandler;

    NSDictionary *providerConfig = self.protocolConfiguration.providerConfiguration;
    if (!providerConfig) {
        NSError *err = [NSError errorWithDomain:@"nodeshift.vpn"
                                          code:1001
                                      userInfo:@{NSLocalizedDescriptionKey: @"No provider config"}];
        completionHandler(err);
        return;
    }

    NSString *host    = providerConfig[@"server_host"]   ?: @"";
    NSNumber *portNum = providerConfig[@"server_port"]   ?: @(443);
    NSString *uuid    = providerConfig[@"uuid"]          ?: @"";
    NSString *pubKey  = providerConfig[@"public_key"]    ?: @"";
    NSString *shortId = providerConfig[@"short_id"]      ?: @"";
    NSString *sni     = providerConfig[@"sni"]           ?: host;

    if (host.length == 0 || uuid.length == 0) {
        NSError *err = [NSError errorWithDomain:@"nodeshift.vpn"
                                          code:1002
                                      userInfo:@{NSLocalizedDescriptionKey: @"Invalid config: host/uuid missing"}];
        completionHandler(err);
        return;
    }

    NSVPNServerConfig *cfg = [[NSVPNServerConfig alloc] init];
    cfg.host     = host;
    cfg.port     = portNum.unsignedShortValue;
    cfg.uuid     = uuid;
    cfg.publicKey = pubKey;
    cfg.shortId  = shortId;
    cfg.sni      = sni;

    LOG("Connecting to %{public}s:%u", host.UTF8String, cfg.port);

    self.protocolHandler = [[ProtocolHandler alloc] initWithConfig:cfg queue:self.ioQueue];
    self.protocolHandler.delegate = self;

    self.netMonitor = [[NetworkMonitor alloc] init];
    self.netMonitor.delegate = self;

    [self connectTunnel];
}

- (void)connectTunnel {
    [self.protocolHandler connectWithCompletion:^(NSError *err) {
        if (err) {
            LOGE("Connection failed: %{public}s", err.localizedDescription.UTF8String);
            [self handleConnectionError:err];
            return;
        }
        [self configureTUNInterface];
    }];
}

- (void)configureTUNInterface {
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"10.89.0.1"]
                                                        subnetMasks:@[@"255.255.255.0"]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];
    ipv4.excludedRoutes = @[
        [[NEIPv4Route alloc] initWithDestinationAddress:@"192.168.0.0" subnetMask:@"255.255.0.0"],
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.0.0.0"   subnetMask:@"255.0.0.0"],
    ];

    NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:@[@"fd00:dead:beef::1"]
                                                      networkPrefixLengths:@[@(64)]];
    ipv6.includedRoutes = @[[NEIPv6Route defaultRoute]];

    NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:@[@"1.1.1.1", @"8.8.8.8"]];
    dns.matchDomains = @[@""];

    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:
            self.protocolHandler.remoteAddress];
    settings.MTU              = @(kTunnelMTU);
    settings.IPv4Settings     = ipv4;
    settings.IPv6Settings     = ipv6;
    settings.DNSSettings      = dns;

    __weak typeof(self) weak = self;
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError *err) {
        __strong typeof(weak) self = weak;
        if (!self) return;
        if (err) {
            LOGE("setTunnelNetworkSettings failed: %{public}s", err.localizedDescription.UTF8String);
            if (self.startCompletion) {
                self.startCompletion(err);
                self.startCompletion = nil;
            }
            return;
        }
        LOG("TUN configured, MTU=%u", kTunnelMTU);
        self.tunnelStartTime = [NSDate timeIntervalSinceReferenceDate];
        self.reconnectCount  = 0;
        [self startPacketForwarding];
        [self startStatsTimer];
        [self.netMonitor start];

        if (self.startCompletion) {
            self.startCompletion(nil);
            self.startCompletion = nil;
        }
    }];
}

// ── Packet forwarding ─────────────────────────────────────────────────────────

- (void)startPacketForwarding {
    LOG("Starting packet forwarding");
    [self readPacketsFromTUN];
}

- (void)readPacketsFromTUN {
    __weak typeof(self) weak = self;
    [self.packetFlow readPacketObjectsWithCompletionHandler:^(NSArray<NEPacket *> *packets) {
        __strong typeof(weak) self = weak;
        if (!self || self.intentionalStop) return;

        for (NEPacket *pkt in packets) {
            self.totalTxBytes += pkt.data.length;
            [self.protocolHandler sendPacket:pkt.data];
        }
        [self readPacketsFromTUN]; // continuous read
    }];
}

// ── ProtocolHandlerDelegate ───────────────────────────────────────────────────

- (void)protocolHandler:(ProtocolHandler *)handler didReceivePacket:(NSData *)data {
    self.totalRxBytes += data.length;
    NEPacket *pkt = [[NEPacket alloc] initWithData:data
                                      protocolFamily:self.detectProtocolFamily(data)];
    [self.packetFlow writePacketObjects:@[pkt]];
}

- (void)protocolHandler:(ProtocolHandler *)handler didDisconnectWithError:(NSError *)error {
    if (self.intentionalStop) {
        LOG("Intentional disconnect");
        return;
    }
    LOGE("Unexpected disconnect: %{public}s", error.localizedDescription.UTF8String);
    [self handleConnectionError:error];
}

// ── Reconnection logic ────────────────────────────────────────────────────────

- (void)handleConnectionError:(NSError *)error {
    if (self.intentionalStop) return;

    if (self.reconnectCount >= kMaxReconnectCount) {
        LOGE("Max reconnect attempts reached, stopping tunnel");
        [self cancelTunnelWithError:error];
        return;
    }

    self.reconnectCount++;
    NSTimeInterval delay = kReconnectDelay * (1 << MIN(self.reconnectCount - 1, 4));
    LOG("Reconnect #%ld in %.1fs", (long)self.reconnectCount, delay);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   self.controlQueue, ^{
        if (!self.intentionalStop) [self connectTunnel];
    });
}

// ── NetworkMonitorDelegate ────────────────────────────────────────────────────

- (void)networkMonitorDidDetectNetworkChange:(NetworkMonitor *)monitor {
    LOG("Network change detected, reconnecting");
    self.reconnectCount = 0;
    [self.protocolHandler disconnect];
    [self connectTunnel];
}

// ── Stats timer ───────────────────────────────────────────────────────────────

- (void)startStatsTimer {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statsTimer = [NSTimer scheduledTimerWithTimeInterval:kStatsIntervalSec
                                                           target:self
                                                         selector:@selector(reportStats)
                                                         userInfo:nil
                                                          repeats:YES];
    });
}

- (void)reportStats {
    NSTimeInterval uptime = [NSDate timeIntervalSinceReferenceDate] - self.tunnelStartTime;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.space.nodeshift.vpn"];
    [shared setObject:@{
        @"rx_bytes":  @(self.totalRxBytes),
        @"tx_bytes":  @(self.totalTxBytes),
        @"uptime_sec":@((NSInteger)uptime),
        @"latency_ms":@(self.protocolHandler.lastLatencyMs),
    } forKey:@"tunnel_stats"];
    [shared synchronize];
}

// ── Stop ──────────────────────────────────────────────────────────────────────

- (void)stopTunnelWithReason:(NEProviderStopReason)reason
           completionHandler:(void (^)(void))completionHandler {
    LOG("stopTunnel reason=%ld", (long)reason);
    self.intentionalStop = YES;
    [self.statsTimer invalidate];
    self.statsTimer = nil;
    [self.netMonitor stop];
    [self.protocolHandler disconnect];
    completionHandler();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static sa_family_t detectProtocolFamily(NSData *data) {
    if (data.length < 1) return AF_INET;
    uint8_t version = ((const uint8_t *)data.bytes)[0] >> 4;
    return version == 6 ? AF_INET6 : AF_INET;
}

@end
