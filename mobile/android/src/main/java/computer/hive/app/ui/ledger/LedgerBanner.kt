package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import computer.hive.app.R
import computer.hive.app.ui.state.BannerState
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerBanner — surface.fold-backed informational banner above the list.
 *
 * surface.fold background, no border, no icon, 12dp inset, body text + an
 * optional secondary action label in accent.signal. On permission-denied it
 * slides in below LedgerHeader with a two-line body and an "Open Settings"
 * secondary action label.
 *
 * Banner-priority rule: at most ONE banner at any time;
 * storage > permission > peer-unreachable. Resolved at the LedgerViewModel;
 * this composable simply renders whichever is current.
 *
 * Strings:
 *   - PermissionNotGranted   → `R.string.hive_ledger_permission_banner`.
 *   - PeerUnreachable        → title + body.
 *   - StorageUnreachable     → title + body.
 *
 * The peer-unreachable banner has NO secondary action affordance — it is purely
 * informational (HIVE handles reconnection). The permission-denied banner DOES
 * route to the Settings deep-link via the `onSecondaryAction` callback.
 */
@Composable
fun LedgerBanner(
    banner: BannerState,
    onSecondaryAction: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current

    val (title, body, ctaLabel) = bannerStrings(banner)

    val a11y = body?.let { "$title. $it" } ?: title

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(colors.surfaceFold)
            .padding(dims.bannerInset)
            .semantics { contentDescription = a11y },
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyLarge,
            color = colors.inkPrimary,
        )
        if (body != null) {
            Spacer(Modifier.height(dims.spaceXxs))
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = colors.inkSecondary,
            )
        }
        if (ctaLabel != null) {
            Spacer(Modifier.height(dims.spaceXs))
            Text(
                text = ctaLabel,
                style = MaterialTheme.typography.labelLarge,
                color = colors.accentSignal,
                modifier = Modifier
                    .clickable(onClick = onSecondaryAction)
                    .semantics { role = Role.Button },
            )
        }
    }
}

/**
 * Resolves the strings per banner kind. Triple is (title, body?, cta?).
 */
@Composable
private fun bannerStrings(banner: BannerState): Triple<String, String?, String?> = when (banner) {
    BannerState.PermissionNotGranted -> Triple(
        stringResource(R.string.hive_ledger_permission_banner),
        null,
        // Settings deep-link CTA — reuses the existing permanent-denial dialog
        // "Open HIVE settings" affordance. This banner is the entry-point that
        // routes into the permission surface.
        stringResource(R.string.hive_ble_permanent_denial_cta_primary),
    )
    BannerState.PeerUnreachable -> Triple(
        stringResource(R.string.hive_ledger_peer_unreachable_title),
        stringResource(R.string.hive_ledger_peer_unreachable_body),
        // No CTA — the banner self-dismisses when reconnection succeeds.
        null,
    )
    BannerState.StorageUnreachable -> Triple(
        stringResource(R.string.hive_ledger_storage_unreachable_title),
        stringResource(R.string.hive_ledger_storage_unreachable_body),
        // No CTA — recovery is "free up space, restart this device, then reopen HIVE",
        // a sequence the user performs OUTSIDE the app. Adding a CTA would lie about
        // what HIVE can do here.
        null,
    )
}
