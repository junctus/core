// neo — Android VpnService (scaffold).
//
// Skeleton only: fill in as milestone M8 is built out. It shows where the shared
// Rust core (via UniFFI-generated Kotlin bindings from `neo-ffi`) plugs into
// Android's VpnService. Requires the Android SDK/NDK + Gradle to build.

package co.neo

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
// import uniffi.neo_ffi.generateIdentity   // UniFFI-generated bindings

class NeoVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    // private var engine: NeoEngine? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 1. Must run as a foreground service with a persistent notification (Android 8+).
        // startForeground(NOTIFICATION_ID, buildNotification())

        // 2. Configure and establish the TUN interface.
        val builder = Builder()
            .setSession("neo")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .setMtu(1400)
        tunnel = builder.establish()

        // 3. Load/generate the identity and start the engine on the TUN fd.
        //    val secret = KeyStore.loadOrCreate { generateIdentity() }   // neo-ffi
        //    engine = NeoEngine.start(tunnel!!.fd, secret)               // batched packet loop
        return START_STICKY
    }

    override fun onDestroy() {
        // engine?.stop()
        tunnel?.close()
        super.onDestroy()
    }
}
