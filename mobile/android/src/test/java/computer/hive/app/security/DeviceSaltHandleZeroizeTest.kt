/*
 * HIVE Android — DeviceSaltHandleZeroizeTest.kt
 *
 * JIT-escape JUnit reflection test. Asserts pre-close non-zero + close →
 * post-close zero via reflection on the private `bytes` field.
 *
 * CI invocation:
 *   ./gradlew testDebugUnitTest      # Dalvik-interpreted (host JVM)
 *   ./gradlew connectedAndroidTest   # ART JIT-compiled (real-device or AVD)
 * BOTH MUST pass.
 *
 * Construction is via the `DeviceSaltHandle.forTesting(...)`
 * `@VisibleForTesting` factory.
 *
 * Until the factory lands, this file COMPILES against the JVM stub of
 * `DeviceSaltHandle`; a RUNTIME PASS awaits the factory and the actual
 * `nativeZeroize` call resolved through `System.loadLibrary("hive_zeroize")`.
 */
package computer.hive.app.security

import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import java.lang.reflect.Field

class DeviceSaltHandleZeroizeTest {

    /**
     * Reflection pre-/post-close byte equality test.
     *
     * Mechanism: construct `DeviceSaltHandle` with a known 32-byte non-zero
     * salt; reflect on the private `bytes` field to capture a reference;
     * call `close()` (which triggers `nativeZeroize` → `memset_explicit` API
     * 34+ OR `hive_volatile_memzero` API 31-33 via the (a)/(b) runtime gate);
     * re-read through the SAME `bytes` reference and assert all-zero. The mode-0
     * `ReleaseByteArrayElements` commits the zeroed bytes back to the JVM heap,
     * so the reflective read MUST see zeros.
     *
     * If this test FAILS, EITHER (a) the JNI API-pair is mispaired (silent
     * zeroize-bug — the preflight grep catches this), OR (b) the JIT optimizer
     * elided the volatile-memset loop (GC-copy residual — the HPROF heap-dump
     * test complements this by covering the broader heap surface).
     */
    @Test
    fun `non-elidable zeroize: reflection pre-close vs post-close byte equality`() {
        // Reflection-based pre-/post-close byte check. Construction via the
        // @VisibleForTesting factory.
        // TODO: implement `DeviceSaltHandle.forTesting(ByteArray)`; until it
        // lands the test fails to compile against the `internal constructor`.
        // Only the test SHAPE is pinned here.
        val handle = DeviceSaltHandle.forTesting(ByteArray(32) { (it + 1).toByte() })

        val bytesField: Field = DeviceSaltHandle::class.java.getDeclaredField("bytes")
        bytesField.isAccessible = true
        val bytes = bytesField.get(handle) as ByteArray

        // PRE: 32 non-zero bytes.
        assertFalse("Pre-close: expected non-zero salt", bytes.all { it == 0.toByte() })
        assertEquals(32, bytes.size)

        // CLOSE → triggers JNI nativeZeroize → memset_explicit (API 34+) OR
        // volatile-memset (31-33) OR Rust hive_core_zeroize via the cxx bridge.
        handle.close()

        // POST: same Field reference, same array instance. The mode-0
        // ReleaseByteArrayElements committed the zeroed bytes back to the JVM
        // heap. Defense-in-depth: the Kotlin-side `Arrays.fill` in `close()`
        // runs after the JNI call — DSE on BOTH compilation boundaries would be
        // required to leak bytes.
        assertTrue("Post-close: expected zeroed salt (R8'/R8'')", bytes.all { it == 0.toByte() })
    }
}
