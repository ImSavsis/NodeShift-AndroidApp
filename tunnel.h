/* tunnel.h — NodeShift VPN Android native tunnel interface
 * Manages TUN device lifecycle and packet I/O for the VPN core.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Constants ─────────────────────────────────────────────────────────────── */

#define NS_TUN_MTU              1500
#define NS_TUN_QUEUE_LEN        512
#define NS_TUN_READ_TIMEOUT_MS  200
#define NS_MAX_PACKET_SIZE      65536
#define NS_SESSION_ID_LEN       32
#define NS_MAX_SERVERS          16
#define NS_STATS_INTERVAL_SEC   1
#define NS_RECONNECT_MAX        5
#define NS_RECONNECT_DELAY_MS   2000

/* ─── Types ──────────────────────────────────────────────────────────────────── */

typedef enum {
    NS_TUNNEL_STOPPED   = 0,
    NS_TUNNEL_STARTING  = 1,
    NS_TUNNEL_RUNNING   = 2,
    NS_TUNNEL_PAUSED    = 3,
    NS_TUNNEL_ERROR     = 4,
    NS_TUNNEL_RECONNECTING = 5,
} NsTunnelState;

typedef enum {
    NS_PROTO_VLESS_REALITY = 0,
    NS_PROTO_VLESS_TLS     = 1,
    NS_PROTO_VMESS         = 2,
    NS_PROTO_TROJAN        = 3,
} NsProtocol;

typedef enum {
    NS_ERR_NONE             = 0,
    NS_ERR_TUN_OPEN         = -1,
    NS_ERR_TUN_CONFIGURE    = -2,
    NS_ERR_CONNECT          = -3,
    NS_ERR_AUTH             = -4,
    NS_ERR_HANDSHAKE        = -5,
    NS_ERR_IO               = -6,
    NS_ERR_TIMEOUT          = -7,
    NS_ERR_INVALID_CONFIG   = -8,
    NS_ERR_MEMORY           = -9,
    NS_ERR_CRYPTO           = -10,
} NsError;

typedef struct {
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t dropped_packets;
    uint32_t latency_ms;
    uint32_t uptime_sec;
    NsTunnelState state;
} NsStats;

typedef struct {
    char     host[256];
    uint16_t port;
    char     uuid[37];           /* UUID string, null-terminated */
    char     public_key[64];     /* X25519 public key (base64) */
    char     short_id[17];       /* Reality short ID */
    char     server_name[256];   /* SNI */
    NsProtocol protocol;
    uint8_t  fingerprint;        /* TLS fingerprint index */
} NsServerConfig;

typedef struct {
    NsServerConfig server;
    char           local_address[16]; /* e.g. "10.0.0.1" */
    uint16_t       local_prefix;      /* e.g. 24 */
    char           dns_primary[16];
    char           dns_secondary[16];
    uint32_t       mtu;
    bool           split_tunnel;
    bool           udp_enabled;
    char           session_id[NS_SESSION_ID_LEN + 1];
} NsTunnelConfig;

typedef void (*NsStateCallback)(NsTunnelState state, NsError error, void *user_data);
typedef void (*NsStatsCallback)(const NsStats *stats, void *user_data);

/* ─── Lifecycle ──────────────────────────────────────────────────────────────── */

typedef struct NsTunnel NsTunnel;

NsTunnel *ns_tunnel_create(void);
void      ns_tunnel_destroy(NsTunnel *tunnel);

NsError ns_tunnel_start(NsTunnel *tunnel, const NsTunnelConfig *config, int tun_fd);
NsError ns_tunnel_stop(NsTunnel *tunnel);
NsError ns_tunnel_pause(NsTunnel *tunnel);
NsError ns_tunnel_resume(NsTunnel *tunnel);

/* ─── Callbacks ──────────────────────────────────────────────────────────────── */

void ns_tunnel_set_state_callback(NsTunnel *tunnel, NsStateCallback cb, void *user_data);
void ns_tunnel_set_stats_callback(NsTunnel *tunnel, NsStatsCallback cb, void *user_data);

/* ─── Queries ────────────────────────────────────────────────────────────────── */

NsTunnelState ns_tunnel_get_state(const NsTunnel *tunnel);
NsError       ns_tunnel_get_stats(const NsTunnel *tunnel, NsStats *out_stats);
int           ns_tunnel_measure_latency(NsTunnel *tunnel);

/* ─── Config helpers ─────────────────────────────────────────────────────────── */

NsError ns_config_parse_vless_link(const char *link, NsServerConfig *out);
bool    ns_config_validate(const NsTunnelConfig *config);
void    ns_config_set_defaults(NsTunnelConfig *config);

const char *ns_error_string(NsError err);
const char *ns_state_string(NsTunnelState state);

#ifdef __cplusplus
}
#endif
