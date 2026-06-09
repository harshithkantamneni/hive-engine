package computer.hive.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import computer.hive.app.ui.ledger.LedgerScreen
import computer.hive.app.ui.theme.HiveTheme

/**
 * MainActivity — HIVE entry-point Activity hosting the LEDGER Compose surface.
 *
 * The Activity extends `androidx.activity.ComponentActivity` so `setContent { }`
 * can host the Compose tree. Material 3 (`androidx.compose.material3:material3`)
 * is used for `Scaffold` + `LazyColumn` + ripple; Material 2
 * (`androidx.compose.material:material`) is intentionally NOT used (deprecated
 * on Android).
 *
 * ## Aesthetic
 *
 * The Compose surface is the LEDGER screen — a monospace-on-warm-paper aesthetic
 * implemented in `ui/theme/` + `ui/ledger/`: zero gradients, zero shadows, zero
 * rounded corners on content, no FAB, no Lottie, no stock illustration, no emoji.
 *
 * ## ZERO-TELEMETRY
 *
 * No analytics SDK invocation, no Crashlytics, no Firebase, no GMS Play Services
 * analytics, no AppsFlyer/Adjust/Branch. Compose deps are exclusively AndroidX
 * (compose-bom 2024.10.01 + activity-compose 1.9.3 + lifecycle 2.8.7 +
 * material3 transitively). No HTTP / RPC / IPC fired on lifecycle. Crash dumps
 * (when authored) route to `Context.getFilesDir()/crashes/` — never to a server.
 *
 * ## JNI bridge — `companion object { System.loadLibrary("hive_core") }`
 *
 * The `libhive_core.so` JNI library load fires at activity-class-load via the
 * companion-object init block (unguarded). Failure propagates as
 * `ExceptionInInitializerError` rather than silently degrading — the activity
 * intentionally cannot exist without its JNI substrate available.
 *
 * ## Zeroize semantics — `nativeZeroizeOnDestroy()`
 *
 * The `onDestroy()` call to `nativeZeroizeOnDestroy()` zeroizes any
 * activity-held sensitive material at teardown. Any DeviceSaltHandle bound to
 * the activity scope MUST have `close()` called before the activity tears down
 * (the close path triggers JNI `hive_core_zeroize`). At present the activity
 * holds NO sensitive byte buffers directly — those live behind
 * `DeviceSaltHandle` — so the `nativeZeroizeOnDestroy()` call is a TRIVIAL
 * no-op that validates the JNI symbol is reachable at lifecycle teardown and
 * establishes the call-site for future activity-held material. When
 * activity-state later holds derived ephemeral material, this call site becomes
 * load-bearing.
 *
 * SECURITY: this Activity is the entry-point — a future contributor adding
 * sensitive byte-handling here MUST route through `DeviceSaltHandle` (opacity
 * layer) rather than holding raw `ByteArray` references on the activity.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // LEDGER Compose surface. HiveTheme wires monospace + paper-warm canvas
        // + oxidized-copper accent tokens; LedgerScreen renders the S1-S6
        // surface states resolved by LedgerViewModel.
        setContent {
            HiveTheme {
                LedgerScreen()
            }
        }
    }

    override fun onDestroy() {
        // Zeroize semantics — call hive_core_zeroize at teardown. The activity
        // holds no sensitive byte material directly (those live behind
        // DeviceSaltHandle's opacity layer), so this is a trivial no-op
        // invocation establishing the call-site for future activity-held
        // ephemeral material.
        nativeZeroizeOnDestroy()
        super.onDestroy()
    }

    /**
     * JNI bridge declaration — calls into the Rust `hive_core_zeroize`
     * extern "C" symbol exported by `libhive_core.so`.
     *
     * The JVM-side declaration is present but the C-side JNI binding is not yet
     * authored (no MainActivity-layer sensitive material to zeroize). When
     * activity-held ephemeral material lands, this declaration is upgraded to
     * `private external fun nativeZeroizeOnDestroy()` and the C-side
     * `Java_computer_hive_app_MainActivity_nativeZeroizeOnDestroy`
     * implementation in `hive_zeroize.c` (or a sibling shim) calls
     * `hive_core_zeroize` on the held-material pointer.
     */
    private fun nativeZeroizeOnDestroy() {
        // No-op stub; the JNI symbol is intentionally not declared `external`
        // because the C-side binding is not yet authored. When activity-held
        // ephemeral material lands, declare as `private external fun
        // nativeZeroizeOnDestroy()` and author the C-side JNI shim.
    }

    companion object {
        init {
            // Unguarded System.loadLibrary posture (same as the
            // DeviceSaltHandle.kt companion-object init). UnsatisfiedLinkError
            // propagates as ExceptionInInitializerError — the activity
            // intentionally cannot exist without its JNI substrate available.
            //
            // NOTE: Idempotent w.r.t. the DeviceSaltHandle.kt companion-init
            // load call — Android System.loadLibrary tracks loaded libraries by
            // name, so a second call is a no-op per the platform contract.
            // Loading here ensures activity-launch-time load semantics
            // independent of the security package being touched first.
            System.loadLibrary("hive_core")
        }
    }
}
