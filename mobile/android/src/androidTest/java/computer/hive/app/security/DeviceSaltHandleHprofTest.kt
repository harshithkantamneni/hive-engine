/*
 * HIVE Android — DeviceSaltHandleHprofTest.kt
 *
 * HPROF heap-dump CI gate (instrumentation test). NECESSARY-BUT-NOT-SUFFICIENT:
 * the test catches surviving salt bytes in the post-close heap, but cannot rule
 * out copies retained by JIT-compiled code paths off the managed heap.
 *
 * CI invocation:
 *   ./gradlew connectedAndroidTest    # AVD matrix: API 31, 33, 34, 35
 *                                       # (the four corners of the (a)/(b)
 *                                       # runtime-gate behavior).
 *   Cadence: pre-GA acceptance ONLY; NOT per-build (HPROF dump + parse is too
 *   slow for the per-push gate).
 *
 * Construction is via the `DeviceSaltHandle.forTesting(...)` factory.
 *
 * The helper `countByteSequenceOccurrences` is a `TODO()`; only the test SHAPE
 * is pinned here.
 */
package computer.hive.app.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.assertEquals
import android.os.Debug
import java.io.File

@RunWith(AndroidJUnit4::class)
class DeviceSaltHandleHprofTest {

    /**
     * Post-close heap-dump byte-sequence-match assertion.
     *
     * Mechanism:
     *   1. Construct DeviceSaltHandle with a known 32-byte non-zero salt.
     *   2. close() → triggers nativeZeroize via the (a)/(b) runtime gate.
     *   3. Force GC + finalization to flush retained references.
     *   4. Dump HPROF to disk via android.os.Debug.dumpHprofData(...).
     *   5. Read HPROF bytes; scan for byte-sequence match against pre-close salt.
     *   6. Assert match-count == 0.
     *
     * Defense-in-depth note:
     *   GC-copy retention can leave salt bytes outside the managed heap
     *   surface that HPROF captures (e.g., JIT codegen literal pools, pinned
     *   off-heap NIO direct buffers). This check is necessary-but-not-sufficient.
     *   Advertising-identity rotation cadence + the plaintext-MUST-stay-on-device
     *   rule are the orthogonal mitigations for the residual.
     */
    @Test
    fun `post-close heap dump contains zero matches of pre-close salt`() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val preCloseSalt = ByteArray(32) { (it + 1).toByte() }
        // TODO: implement the forTesting factory.
        val handle = DeviceSaltHandle.forTesting(preCloseSalt.copyOf())
        handle.close()

        // GC pressure to force any retained references off the heap.
        // (System.gc() is a request, not a mandate; the AVD matrix
        // mitigates the per-device variance.)
        System.gc()
        System.runFinalization()

        val hprofPath = File(context.cacheDir, "post_close.hprof").absolutePath
        Debug.dumpHprofData(hprofPath)

        // Parse with eclipse-mat or a perfetto static analyzer; for this stub we
        // read raw bytes + scan with the helper.
        val hprofBytes = File(hprofPath).readBytes()
        val matchCount = countByteSequenceOccurrences(hprofBytes, preCloseSalt)
        assertEquals(
            "post-close heap must contain zero matches of pre-close salt",
            0,
            matchCount,
        )
    }

    /**
     * Boyer-Moore or KMP byte-sequence scan helper.
     *
     * **TODO: full implementation.** The stub deliberately uses `TODO()` so a CI
     * run surfaces the dependency immediately rather than pretending to pass.
     *
     * When this lands: prefer KMP over Boyer-Moore for 32-byte needles (the BM
     * bad-character table win is marginal at small needle sizes; KMP's per-byte
     * cost dominates and is more cache-friendly).
     */
    private fun countByteSequenceOccurrences(haystack: ByteArray, needle: ByteArray): Int = TODO(
        "byte-sequence scan helper. " +
            "Implementation choice: KMP preferred over Boyer-Moore for 32-byte needles."
    )
}
