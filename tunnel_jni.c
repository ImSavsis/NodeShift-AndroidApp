/* tunnel_jni.c — JNI bridge between Android Java/Kotlin and the native tunnel core.
 *
 * Exposes NsTunnel lifecycle and stats to the Android VpnService via JNI.
 * Called from TunnelManager.kt running in a dedicated foreground service.
 */

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/tunnel.h"

#define TAG "NsTunnelJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/* ─── Global state ───────────────────────────────────────────────────────────── */

static NsTunnel         *g_tunnel      = NULL;
static pthread_mutex_t   g_lock        = PTHREAD_MUTEX_INITIALIZER;
static JavaVM           *g_jvm         = NULL;
static jobject           g_callback    = NULL;   /* TunnelCallbackImpl ref */
static jclass            g_cb_class    = NULL;

/* ─── JNI_OnLoad ─────────────────────────────────────────────────────────────── */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("Failed to get JNI environment");
        return JNI_ERR;
    }
    LOGI("NsTunnel JNI loaded, version %d", NS_TUN_MTU);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
        if (g_callback) (*env)->DeleteGlobalRef(env, g_callback);
        if (g_cb_class)  (*env)->DeleteGlobalRef(env, g_cb_class);
    }
    g_jvm = g_callback = g_cb_class = NULL;
}

/* ─── Helper: attach current thread to JVM ───────────────────────────────────── */

static JNIEnv *attach_thread(void) {
    if (!g_jvm) return NULL;
    JNIEnv *env = NULL;
    int ret = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (ret == JNI_EDETACHED) {
        JavaVMAttachArgs args = { JNI_VERSION_1_6, "NsTunnelThread", NULL };
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, &args) != JNI_OK) {
            LOGE("AttachCurrentThread failed");
            return NULL;
        }
    } else if (ret != JNI_OK) {
        LOGE("GetEnv failed: %d", ret);
        return NULL;
    }
    return env;
}

/* ─── Callbacks from native → Java ──────────────────────────────────────────── */

static void on_state_changed(NsTunnelState state, NsError error, void *user_data) {
    (void)user_data;
    JNIEnv *env = attach_thread();
    if (!env || !g_callback || !g_cb_class) return;

    jmethodID mid = (*env)->GetMethodID(env, g_cb_class, "onStateChanged", "(II)V");
    if (!mid) { LOGE("onStateChanged method not found"); return; }

    (*env)->CallVoidMethod(env, g_callback, mid, (jint)state, (jint)error);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
}

static void on_stats_updated(const NsStats *stats, void *user_data) {
    (void)user_data;
    if (!stats) return;

    JNIEnv *env = attach_thread();
    if (!env || !g_callback || !g_cb_class) return;

    jmethodID mid = (*env)->GetMethodID(env, g_cb_class,
        "onStatsUpdated", "(JJJJJII)V");
    if (!mid) { LOGE("onStatsUpdated method not found"); return; }

    (*env)->CallVoidMethod(env, g_callback, mid,
        (jlong)stats->rx_bytes,
        (jlong)stats->tx_bytes,
        (jlong)stats->rx_packets,
        (jlong)stats->tx_packets,
        (jlong)stats->dropped_packets,
        (jint)stats->latency_ms,
        (jint)stats->uptime_sec);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
}

/* ─── JNI exports ────────────────────────────────────────────────────────────── */

JNIEXPORT jlong JNICALL
Java_space_nodeshift_vpn_TunnelManager_nCreate(JNIEnv *env, jobject thiz) {
    (void)thiz;
    pthread_mutex_lock(&g_lock);
    if (g_tunnel) {
        LOGW("Tunnel already exists, destroying old instance");
        ns_tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
    }
    g_tunnel = ns_tunnel_create();
    if (!g_tunnel) {
        LOGE("ns_tunnel_create failed");
        pthread_mutex_unlock(&g_lock);
        return 0L;
    }
    LOGI("Tunnel created: %p", (void *)g_tunnel);
    pthread_mutex_unlock(&g_lock);
    return (jlong)(intptr_t)g_tunnel;
}

JNIEXPORT void JNICALL
Java_space_nodeshift_vpn_TunnelManager_nDestroy(JNIEnv *env, jobject thiz, jlong handle) {
    (void)thiz;
    pthread_mutex_lock(&g_lock);
    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    if (tunnel) {
        ns_tunnel_destroy(tunnel);
        if (g_tunnel == tunnel) g_tunnel = NULL;
        LOGI("Tunnel destroyed");
    }
    pthread_mutex_unlock(&g_lock);
}

JNIEXPORT void JNICALL
Java_space_nodeshift_vpn_TunnelManager_nSetCallback(
        JNIEnv *env, jobject thiz, jlong handle, jobject callback) {
    (void)thiz;
    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    if (!tunnel) return;

    if (g_callback) (*env)->DeleteGlobalRef(env, g_callback);
    if (g_cb_class)  (*env)->DeleteGlobalRef(env, g_cb_class);

    g_callback = (*env)->NewGlobalRef(env, callback);
    g_cb_class  = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));

    ns_tunnel_set_state_callback(tunnel, on_state_changed, NULL);
    ns_tunnel_set_stats_callback(tunnel, on_stats_updated, NULL);
    LOGD("Callbacks registered");
}

JNIEXPORT jint JNICALL
Java_space_nodeshift_vpn_TunnelManager_nStart(
        JNIEnv *env, jobject thiz, jlong handle,
        jstring j_host, jint port, jstring j_uuid,
        jstring j_pub_key, jstring j_short_id, jstring j_sni,
        jint protocol, jint tun_fd) {
    (void)thiz;

    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    if (!tunnel) return (jint)NS_ERR_INVALID_CONFIG;

    const char *host     = (*env)->GetStringUTFChars(env, j_host,     NULL);
    const char *uuid     = (*env)->GetStringUTFChars(env, j_uuid,     NULL);
    const char *pub_key  = (*env)->GetStringUTFChars(env, j_pub_key,  NULL);
    const char *short_id = (*env)->GetStringUTFChars(env, j_short_id, NULL);
    const char *sni      = (*env)->GetStringUTFChars(env, j_sni,      NULL);

    NsTunnelConfig cfg;
    ns_config_set_defaults(&cfg);

    strncpy(cfg.server.host,        host,     sizeof(cfg.server.host)     - 1);
    strncpy(cfg.server.uuid,        uuid,     sizeof(cfg.server.uuid)     - 1);
    strncpy(cfg.server.public_key,  pub_key,  sizeof(cfg.server.public_key)- 1);
    strncpy(cfg.server.short_id,    short_id, sizeof(cfg.server.short_id) - 1);
    strncpy(cfg.server.server_name, sni,      sizeof(cfg.server.server_name)-1);
    cfg.server.port     = (uint16_t)port;
    cfg.server.protocol = (NsProtocol)protocol;

    (*env)->ReleaseStringUTFChars(env, j_host,     host);
    (*env)->ReleaseStringUTFChars(env, j_uuid,     uuid);
    (*env)->ReleaseStringUTFChars(env, j_pub_key,  pub_key);
    (*env)->ReleaseStringUTFChars(env, j_short_id, short_id);
    (*env)->ReleaseStringUTFChars(env, j_sni,      sni);

    if (!ns_config_validate(&cfg)) {
        LOGE("Invalid tunnel config");
        return (jint)NS_ERR_INVALID_CONFIG;
    }

    LOGI("Starting tunnel → %s:%d proto=%d fd=%d", cfg.server.host, port, protocol, tun_fd);
    NsError err = ns_tunnel_start(tunnel, &cfg, tun_fd);
    if (err != NS_ERR_NONE) {
        LOGE("ns_tunnel_start failed: %s", ns_error_string(err));
    }
    return (jint)err;
}

JNIEXPORT jint JNICALL
Java_space_nodeshift_vpn_TunnelManager_nStop(JNIEnv *env, jobject thiz, jlong handle) {
    (void)env; (void)thiz;
    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    if (!tunnel) return (jint)NS_ERR_NONE;
    LOGI("Stopping tunnel");
    return (jint)ns_tunnel_stop(tunnel);
}

JNIEXPORT jint JNICALL
Java_space_nodeshift_vpn_TunnelManager_nGetState(JNIEnv *env, jobject thiz, jlong handle) {
    (void)env; (void)thiz;
    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    if (!tunnel) return (jint)NS_TUNNEL_STOPPED;
    return (jint)ns_tunnel_get_state(tunnel);
}

JNIEXPORT jint JNICALL
Java_space_nodeshift_vpn_TunnelManager_nMeasureLatency(JNIEnv *env, jobject thiz, jlong handle) {
    (void)env; (void)thiz;
    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    if (!tunnel) return -1;
    return (jint)ns_tunnel_measure_latency(tunnel);
}

JNIEXPORT jlongArray JNICALL
Java_space_nodeshift_vpn_TunnelManager_nGetStats(JNIEnv *env, jobject thiz, jlong handle) {
    (void)thiz;
    NsTunnel *tunnel = (NsTunnel *)(intptr_t)handle;
    NsStats stats = {0};
    if (tunnel) ns_tunnel_get_stats(tunnel, &stats);

    jlongArray arr = (*env)->NewLongArray(env, 7);
    if (!arr) return NULL;

    jlong buf[7] = {
        (jlong)stats.rx_bytes,
        (jlong)stats.tx_bytes,
        (jlong)stats.rx_packets,
        (jlong)stats.tx_packets,
        (jlong)stats.dropped_packets,
        (jlong)stats.latency_ms,
        (jlong)stats.uptime_sec,
    };
    (*env)->SetLongArrayRegion(env, arr, 0, 7, buf);
    return arr;
}
