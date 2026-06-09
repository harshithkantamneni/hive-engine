package computer.hive.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * LocalHiveColors — composition-local carrier for HIVE's semantic color tokens.
 *
 * The `LocalHiveColors` composition-local carries semantic tokens
 * (`accent.signal`, `state.warn`, etc.) that don't fit M3's
 * primary/secondary/tertiary/error scheme. Components reference HIVE tokens via
 * `LocalHiveColors.current` and fall back to M3 tokens for
 * surface/onSurface/etc.
 */
val LocalHiveColors = staticCompositionLocalOf { HiveLightSemanticTokens }

/**
 * HiveTheme — root Compose theme for the LEDGER MainActivity surface.
 *
 * Approach: Material 3 with custom theme tokens. M3 ships ColorScheme,
 * Typography, and Shapes as composition-locals; we use the M3 plumbing for
 * accessibility/state-layer compatibility, but populate it with HIVE tokens. We
 * do NOT use `MaterialTheme.dynamicColor` (the Android 12+ Material You
 * wallpaper-derived palette) — HIVE's color system is identity-fixed, not
 * user-derived.
 *
 * Two-layer plumbing:
 *   1. `MaterialTheme(colorScheme, typography, shapes)` populates M3's
 *      composition-local plumbing with HIVE-shaped values for
 *      surface/onSurface/primary/onPrimary/etc. — HIVE tokens project onto
 *      the M3 type-system so M3 primitives (Scaffold, ripple, IME insets)
 *      pick up HIVE colors automatically.
 *   2. `CompositionLocalProvider(LocalHiveColors provides ...)` provides the
 *      semantic tokens M3's scheme cannot express (accent.signal, state.warn,
 *      ink.dim, etc.). HIVE composables read these via `LocalHiveColors.current`.
 *
 * Aesthetic constraints:
 *   - `dynamicColor` explicitly NOT used (HIVE's color system is identity-fixed,
 *     not user-derived). Wallpaper-derived M3 palettes drift toward
 *     purple-pink-pastel which the LEDGER surface MUST resist.
 *   - All shapes 0dp (kills M3's default 4-16dp rounding).
 *   - All typography monospace (M3's default Roboto is replaced wholesale on the
 *     content surface).
 */
@Composable
fun HiveTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val semantic = if (darkTheme) HiveDarkSemanticTokens else HiveLightSemanticTokens

    // Project HIVE semantic tokens onto M3 ColorScheme so M3 primitives
    // (Scaffold, ripple, surface) pick up the right colors automatically.
    // HIVE-specific tokens (accent.signal, state.warn) are NOT mapped here —
    // composables read them via `LocalHiveColors.current`.
    val colorScheme = if (darkTheme) {
        darkColorScheme(
            primary = semantic.accentSignal,
            onPrimary = semantic.surfaceCanvas,
            background = semantic.surfaceCanvas,
            onBackground = semantic.inkPrimary,
            surface = semantic.surfaceCanvas,
            onSurface = semantic.inkPrimary,
            surfaceVariant = semantic.surfaceFold,
            onSurfaceVariant = semantic.inkSecondary,
            outline = semantic.inkDim,
            error = semantic.stateError,
            onError = semantic.surfaceCanvas,
        )
    } else {
        lightColorScheme(
            primary = semantic.accentSignal,
            onPrimary = semantic.surfaceCanvas,
            background = semantic.surfaceCanvas,
            onBackground = semantic.inkPrimary,
            surface = semantic.surfaceCanvas,
            onSurface = semantic.inkPrimary,
            surfaceVariant = semantic.surfaceFold,
            onSurfaceVariant = semantic.inkSecondary,
            outline = semantic.inkDim,
            error = semantic.stateError,
            onError = semantic.surfaceCanvas,
        )
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = HiveTypography,
        shapes = HiveShapes,
    ) {
        CompositionLocalProvider(
            LocalHiveColors provides semantic,
            LocalHiveDimensions provides HiveDimensions(),
        ) {
            content()
        }
    }
}
