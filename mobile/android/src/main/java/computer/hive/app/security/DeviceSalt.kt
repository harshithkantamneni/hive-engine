package computer.hive.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android device-salt storage: StrongBox-wrapped AES-GCM of a 32-byte salt
 * stored as ciphertext in `Context.getFilesDir()/hive.device-salt.v1.aes-gcm`.
 * Returns a [DeviceSaltHandle] opaque wrapper rather than raw bytes.
 *
 * SECURITY INVARIANTS (absolute, "under any circumstance"):
 *   - Salt plaintext MUST NOT be exported, synced, backed up to Google
 *     Drive, logged, printed, emitted in crash reports, serialized over
 *     IPC, or transmitted off-device.
 *   - Callers operate on the returned [DeviceSaltHandle] via its `use { }`
 *     scope function and [DeviceSaltHandle.deriveHkdfSha256]; there is no
 *     public accessor that returns raw salt bytes. The wrapper's close()
 *     zeroizes the backing buffer.
 */
object DeviceSalt {

    /** StrongBox-backed AES-GCM wrapping-key alias. */
    private const val KEY_ALIAS = "hive.device-salt.v1"

    /** Ciphertext filename in `Context.getFilesDir()`. */
    private const val CIPHERTEXT_FILENAME = "hive.device-salt.v1.aes-gcm"

    /** AndroidKeyStore provider name — the canonical Android Keystore. */
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    /** Salt length — 32 bytes (SHA-256 HashLen, RFC 5869 §3.1). */
    private const val SALT_LEN_BYTES = 32

    /**
     * AES-GCM authentication tag length — 128 bits, the AES-GCM default.
     *
     * Held as bits (not bytes) because [GCMParameterSpec] accepts the tag
     * length parameter in bits. Use [GCM_TAG_LEN_BYTES] where a byte count
     * is required (e.g. on-disk blob size arithmetic).
     */
    private const val GCM_TAG_LEN_BITS = 128

    /** AES-GCM authentication tag length in bytes — 16. Derived from [GCM_TAG_LEN_BITS]. */
    private const val GCM_TAG_LEN_BYTES = GCM_TAG_LEN_BITS / 8

    /** AES-GCM IV length — 12 bytes (96 bits), the NIST SP 800-38D recommendation. */
    private const val GCM_IV_LEN_BYTES = 12

    /** On-disk blob format version — bumped if the [1B version][12B IV][ct||16B tag] layout ever changes. */
    private const val BLOB_VERSION_BYTE: Byte = 0x01

    /** Minimum valid on-disk blob size in bytes — 1 version byte + IV + 32B-salt-ciphertext + 16B GCM tag. */
    private const val BLOB_MIN_SIZE_BYTES = 1 + GCM_IV_LEN_BYTES + SALT_LEN_BYTES + GCM_TAG_LEN_BYTES

    /**
     * Generate or load the per-device 32-byte blinding salt used for
     * HKDF-blinded trustee-list alias derivation and BLE advertising identity
     * rotation.
     *
     * Returns a [DeviceSaltHandle] opaque wrapper. The wrapper zeroizes its
     * backing buffer on [DeviceSaltHandle.close] (use via `.use { ... }` scope
     * function) and exposes no raw-bytes accessor; the only public derivation
     * path is [DeviceSaltHandle.deriveHkdfSha256].
     *
     * On first call: generates 32B via [SecureRandom.getInstanceStrong],
     * AES-GCM-wraps via a StrongBox-backed key, writes the ciphertext blob to
     * `context.filesDir.resolve(CIPHERTEXT_FILENAME)`, wraps the plaintext in a
     * [DeviceSaltHandle], and zeroizes the local plaintext copy.
     *
     * On subsequent calls: loads the ciphertext, unwraps via AndroidKeyStore
     * StrongBox, wraps, zeroizes the local plaintext copy, returns the handle.
     *
     * Failure modes (fail-closed):
     *   - [StrongBoxUnavailableException] on StrongBox-missing devices —
     *     propagated so the caller can surface the UI chip.
     *   - [SecurityException] on AndroidKeyStore failure — propagated.
     *
     * SECURITY: callers MUST use the returned handle within a `use { }` block
     * so `close()` fires at scope exit, zeroizing the salt bytes. Extended
     * retention of a live handle is an anti-pattern.
     */
    @JvmStatic
    @Throws(StrongBoxUnavailableException::class, SecurityException::class)
    fun generateOrLoadDeviceSalt(context: Context): DeviceSaltHandle {
        val ciphertextFile = File(context.filesDir, CIPHERTEXT_FILENAME)
        val saltBytes = if (ciphertextFile.exists()) {
            loadExisting(ciphertextFile)
        } else {
            generateFresh(ciphertextFile)
        }
        try {
            // SECURITY: DeviceSaltHandle.wrap() defensively copies the bytes
            // into the handle's backing buffer; we zeroize OUR local copy in
            // the `finally` block below so the plaintext does not out-live
            // this stack frame.
            return DeviceSaltHandle.wrap(saltBytes)
        } finally {
            // SECURITY: zeroize the local plaintext ByteArray. The handle now
            // owns the only in-memory copy; on handle.close() that copy is
            // zeroized. DO NOT remove this line — it is the single-copy
            // invariant.
            java.util.Arrays.fill(saltBytes, 0x00.toByte())
        }
    }

    // --- first-launch path ----------------------------------------------------

    private fun generateFresh(ciphertextFile: File): ByteArray {
        // SECURITY: SecureRandom.getInstanceStrong() selects an algorithm from
        // the `securerandom.strongAlgorithms` Security property, per the
        // Android Developers Javadoc.
        val saltBytes = ByteArray(SALT_LEN_BYTES)
        SecureRandom.getInstanceStrong().nextBytes(saltBytes)

        val wrappingKey = getOrCreateWrappingKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        // SECURITY: IV is randomly drawn by the Cipher on init — we MUST
        // read it back from `cipher.iv` and prepend to the ciphertext blob
        // so unwrap works on subsequent boots.
        val ivBytes = cipher.iv
        // AndroidKeyStore AES/GCM/NoPadding is contractually 12-byte IV; a
        // non-12-byte IV would indicate a non-AndroidKeyStore provider silently
        // resolved (JCE-provider-injection vector). Fail-closed exact-equality.
        require(ivBytes.size == GCM_IV_LEN_BYTES) {
            "AES-GCM IV length must be exactly $GCM_IV_LEN_BYTES bytes; got ${ivBytes.size}"
        }
        val ciphertextBytes = cipher.doFinal(saltBytes)
        // AES-GCM ciphertext is plaintext-size + tag-size; defense-in-depth
        // against a provider that emits a non-128-bit tag.
        require(ciphertextBytes.size == SALT_LEN_BYTES + GCM_TAG_LEN_BYTES) {
            "AES-GCM ciphertext length must be ${SALT_LEN_BYTES + GCM_TAG_LEN_BYTES} bytes " +
                "(salt $SALT_LEN_BYTES + tag $GCM_TAG_LEN_BYTES); got ${ciphertextBytes.size}"
        }

        // On-disk blob format: [1B version=BLOB_VERSION_BYTE][12B IV][ciphertext||16B tag]
        val blobBytes = ByteArray(1 + GCM_IV_LEN_BYTES + ciphertextBytes.size)
        blobBytes[0] = BLOB_VERSION_BYTE
        System.arraycopy(ivBytes, 0, blobBytes, 1, GCM_IV_LEN_BYTES)
        System.arraycopy(ciphertextBytes, 0, blobBytes, 1 + GCM_IV_LEN_BYTES, ciphertextBytes.size)
        // SECURITY: writeBytes is atomic-enough for first-launch; the blob is
        // small (BLOB_MIN_SIZE_BYTES bytes) and power-loss here is equivalent
        // to never having launched — next launch regenerates.
        ciphertextFile.writeBytes(blobBytes)
        return saltBytes
    }

    // --- subsequent-launch path -----------------------------------------------

    private fun loadExisting(ciphertextFile: File): ByteArray {
        val blobBytes = ciphertextFile.readBytes()
        require(blobBytes.size >= BLOB_MIN_SIZE_BYTES) {
            "device-salt ciphertext blob corrupt: size=${blobBytes.size} (expected ≥ $BLOB_MIN_SIZE_BYTES)"
        }
        require(blobBytes[0] == BLOB_VERSION_BYTE) {
            "device-salt ciphertext blob version unsupported: ${blobBytes[0]} (expected $BLOB_VERSION_BYTE)"
        }
        val ivBytes = blobBytes.copyOfRange(1, 1 + GCM_IV_LEN_BYTES)
        // ivBytes.size is exactly GCM_IV_LEN_BYTES by the copyOfRange slice
        // above — but we assert-tight to catch any future refactor that slices
        // differently (fail-closed over silently).
        require(ivBytes.size == GCM_IV_LEN_BYTES) {
            "decoded IV length must be exactly $GCM_IV_LEN_BYTES bytes; got ${ivBytes.size}"
        }
        val ciphertextBytes = blobBytes.copyOfRange(1 + GCM_IV_LEN_BYTES, blobBytes.size)

        val wrappingKey = getOrCreateWrappingKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            wrappingKey,
            GCMParameterSpec(GCM_TAG_LEN_BITS, ivBytes),
        )
        // SECURITY: the decrypted salt goes directly to the caller; we do not
        // retain a reference, we do not log, we do not stringify.
        return cipher.doFinal(ciphertextBytes)
    }

    // --- StrongBox wrapping key provisioning ----------------------------------

    private fun getOrCreateWrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        // Wrapping-key spec:
        //   KeyGenParameterSpec.Builder("hive.device-salt.v1",
        //     PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
        //       .setBlockModes(BLOCK_MODE_GCM)
        //       .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
        //       .setIsStrongBoxBacked(true)
        //       .setUserAuthenticationRequired(false)
        //       .build()
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // StrongBox-backed. On StrongBoxUnavailableException we fail-closed
            // — do NOT silently fall back to TEE-only.
            .setIsStrongBoxBacked(true)
            // Alias derivation is cold-start pre-biometric — hardware-binding
            // via StrongBox is the defense, not biometric-gating. DO NOT flip
            // this to `true`.
            .setUserAuthenticationRequired(false)
            .build()

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER,
        )
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
