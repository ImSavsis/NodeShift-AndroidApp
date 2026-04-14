// NetworkMonitor.mm — iOS network connectivity monitoring for auto-reconnect

#import "NetworkMonitor.h"
#import <Network/Network.h>
#import <os/log.h>

static os_log_t kLog = nil;

@interface NetworkMonitor ()
@property (nonatomic, strong) nw_path_monitor_t monitor;
@property (nonatomic, strong) dispatch_queue_t   queue;
@property (nonatomic, assign) nw_path_status_t   lastStatus;
@end

@implementation NetworkMonitor

+ (void)initialize {
    if (self == [NetworkMonitor class]) {
        kLog = os_log_create("space.nodeshift.vpn.extension", "NetMonitor");
    }
}

- (instancetype)init {
    if (self = [super init]) {
        _queue = dispatch_queue_create("nodeshift.vpn.netmonitor",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0));
        _lastStatus = nw_path_status_invalid;
    }
    return self;
}

- (void)start {
    __weak typeof(self) weak = self;
    self.monitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(self.monitor, self.queue);
    nw_path_monitor_set_update_handler(self.monitor, ^(nw_path_t path) {
        __strong typeof(weak) self = weak;
        if (!self) return;

        nw_path_status_t status = nw_path_get_status(path);
        if (status == self.lastStatus) return;

        os_log_with_type(kLog, OS_LOG_TYPE_INFO, "Network status: %d → %d",
                         (int)self.lastStatus, (int)status);

        nw_path_status_t prev = self.lastStatus;
        self.lastStatus = status;

        if (status == nw_path_status_satisfied && prev != nw_path_status_invalid) {
            // Network came back — trigger reconnect
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.delegate networkMonitorDidDetectNetworkChange:self];
            });
        }
    });
    nw_path_monitor_start(self.monitor);
    os_log_with_type(kLog, OS_LOG_TYPE_INFO, "Network monitor started");
}

- (void)stop {
    if (self.monitor) {
        nw_path_monitor_cancel(self.monitor);
        self.monitor = nil;
    }
    os_log_with_type(kLog, OS_LOG_TYPE_INFO, "Network monitor stopped");
}

- (BOOL)isConnected {
    return self.lastStatus == nw_path_status_satisfied;
}

- (NSString *)connectionType {
    if (self.lastStatus != nw_path_status_satisfied) return @"none";
    // In real implementation, check nw_path_uses_interface_type
    return @"unknown";
}

@end
