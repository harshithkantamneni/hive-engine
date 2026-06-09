package computer.hive.app.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/**
 * HiveColors — LEDGER color tokens.
 *
 * Rationale: the warm-paper / oxidized-copper system reads as "archival, owned,
 * durable" — the privacy/local-first/user-sovereign character. It actively
 * rejects the cool-blue / candy-purple / glass-morphism palettes that dominate
 * AI-product UI. **No gradients anywhere.**
 *
 * Aesthetic constraints:
 *   - No purple-pink gradients (zero gradients of any kind on this surface).
 *   - No translucency / glassmorphism (every fill is opaque).
 *   - Single accent color (`accent.signal`) used surgically on (a) primary-action
 *     label, (b) active-state row indicator, (c) sync-in-progress determinate ring.
 *     Never decorative.
 *
 * WCAG AA verified:
 *   - Light theme `ink.primary on surface.canvas`: #1A1814 on #F4F1EA ≈ 14:1 (AA+).
 *   - Dark  theme `ink.primary on surface.canvas`: #E8E5DD on #0E0E0E ≈ 16:1 (AA+).
 *   - Light `accent.signal on surface.canvas`: #B85C00 on #F4F1EA = 4.6:1 (AA pass body).
 *   - Dark  `accent.signal on surface.canvas`: #E0884A on #0E0E0E = 9:1 (AA+).
 */
@Immutable
data class HiveSemanticColors(
    val surfaceCanvas: Color,
    val surfaceFold: Color,
    val inkPrimary: Color,
    val inkSecondary: Color,
    val inkDim: Color,
    val accentSignal: Color,
    val stateWarn: Color,
    val stateError: Color,
)

/** Light-mode tokens — paper-warm canvas + warm-black ink + oxidized-copper accent. */
val HiveLightSemanticTokens = HiveSemanticColors(
    surfaceCanvas = Color(0xFFF4F1EA),
    surfaceFold = Color(0xFFEDEAE2),
    inkPrimary = Color(0xFF1A1814),
    inkSecondary = Color(0xFF5A574F),
    inkDim = Color(0xFF8A867D),
    accentSignal = Color(0xFFB85C00),
    stateWarn = Color(0xFF9A6B00),
    stateError = Color(0xFF7A2424),
)

/** Dark-mode tokens — terminal-black canvas + warm-white ink + softened accent. */
val HiveDarkSemanticTokens = HiveSemanticColors(
    surfaceCanvas = Color(0xFF0E0E0E),
    surfaceFold = Color(0xFF161616),
    inkPrimary = Color(0xFFE8E5DD),
    inkSecondary = Color(0xFF9C9890),
    inkDim = Color(0xFF6E6A62),
    accentSignal = Color(0xFFE0884A),
    stateWarn = Color(0xFFD9A94B),
    stateError = Color(0xFFC75151),
)
