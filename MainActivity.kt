package space.nodeshift.vpn

import android.content.Intent
import android.net.Uri
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private val CHANNEL = "space.nodeshift.vpn/browser"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "launchCustomTab" -> {
                        val url = call.argument<String>("url") ?: ""
                        launchChromeCustomTab(url)
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun launchChromeCustomTab(url: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra("android.support.customtabs.extra.SESSION", null as android.os.Bundle?)
                putExtra("android.support.customtabs.extra.TOOLBAR_COLOR", 0xFF0a0a0a.toInt())
            }
            startActivity(intent)
        } catch (e: Exception) {
            // Fallback: open in default browser
            val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            startActivity(browserIntent)
        }
    }

    // Handle deep link when app is already running (singleTop mode)
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLink(intent)
    }

    private fun handleDeepLink(intent: Intent) {
        val data = intent.data ?: return
        if (data.scheme == "nodeshift" && data.host == "auth") {
            // Flutter router will handle this via GoRouter
        }
    }
}
