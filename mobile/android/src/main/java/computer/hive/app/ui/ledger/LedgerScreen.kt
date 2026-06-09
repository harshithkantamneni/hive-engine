package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import computer.hive.app.R
import computer.hive.app.ui.state.GlobalSyncState
import computer.hive.app.ui.state.LedgerUiState
import computer.hive.app.ui.state.LedgerViewModel
import computer.hive.app.ui.theme.LocalHiveColors

/**
 * LedgerScreen — top-level composable for the LEDGER MainActivity surface.
 *
 * Takes a LedgerViewModel.
 *
 *   Composable hierarchy:
 *   ```
 *   MainActivity
 *   └── HiveTheme
 *       └── LedgerScreen(viewModel)
 *           └── Scaffold (Material 3, topBar = null)
 *               ├── content = Column
 *               │   ├── LedgerHeader(label)
 *               │   ├── LedgerSyncIndicator(globalSyncProgress) [conditional: S3 only]
 *               │   ├── LedgerBanner(bannerState) [conditional: S4/S5/S6]
 *               │   └── content-region:
 *               │       ├── if Empty: LedgerEmptyState()
 *               │       └── if Populated: LazyColumn { items(rows) { LedgerRow(it); LedgerRule() } }
 *               └── bottomBar = LedgerPrimaryAction(label, onClick)
 *   ```
 *
 * 6-state rendering map:
 *   S1 First-run / empty       → [LedgerUiState.Empty]                                  → LedgerEmptyState()
 *   S2 Populated                → [LedgerUiState.Populated] no banner, no sync          → LazyColumn rows
 *   S3 Loading / sync-progress  → [LedgerUiState.Populated] syncState != null           → LedgerSyncIndicator + rows
 *   S4 Permission denied        → [LedgerUiState.Populated] banner = PermissionNotGranted → LedgerBanner
 *   S5 Storage critical         → [LedgerUiState.Populated] banner = StorageUnreachable → LedgerBanner + disabled CTA
 *   S6 Crash-recovery           → [LedgerUiState.Populated] rows[0].isCrashRecovery     → row state.warn accent
 */
@Composable
fun LedgerScreen(
    viewModel: LedgerViewModel = viewModel(),
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val colors = LocalHiveColors.current

    // Storage-critical flag — drives the primary-action disabled state.
    val isStorageCritical = (uiState as? LedgerUiState.Populated)?.banner ==
        computer.hive.app.ui.state.BannerState.StorageUnreachable

    Scaffold(
        modifier = modifier
            .fillMaxSize()
            .background(colors.surfaceCanvas),
        topBar = { /* no top app bar */ },
        bottomBar = {
            LedgerPrimaryAction(
                label = stringResource(R.string.hive_ledger_empty_cta_primary),
                onClick = viewModel::onExtractRequested,
                enabled = !isStorageCritical,
            )
        },
        containerColor = colors.surfaceCanvas,
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(colors.surfaceCanvas),
        ) {
            LedgerHeaderDefault()

            when (val state = uiState) {
                is LedgerUiState.Loading -> {
                    LoadingPanel()
                }
                is LedgerUiState.Empty -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        LedgerEmptyState()
                    }
                }
                is LedgerUiState.Populated -> {
                    PopulatedContent(
                        state = state,
                        onOpenSettings = viewModel::onOpenSettingsRequested,
                        onResumeCrashed = viewModel::onResumeCrashedExtraction,
                        onDiscardCrashed = viewModel::onDiscardCrashedExtraction,
                    )
                }
            }
        }
    }
}

@Composable
private fun LoadingPanel() {
    val colors = LocalHiveColors.current
    Column(
        modifier = Modifier.fillMaxSize().background(colors.surfaceCanvas),
    ) {
        // Initial-load copy — `Reading from this device.`
        Text(
            text = stringResource(R.string.hive_ledger_loading_initial),
            style = MaterialTheme.typography.bodyLarge,
            color = colors.inkSecondary,
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 24.dp),
        )
    }
}

@Composable
private fun PopulatedContent(
    state: LedgerUiState.Populated,
    onOpenSettings: () -> Unit,
    onResumeCrashed: (String) -> Unit,
    onDiscardCrashed: (String) -> Unit,
) {
    val colors = LocalHiveColors.current

    // S3 — global sync indicator (per-row sync glyphs are rendered inside LedgerRow).
    when (val sync = state.syncState) {
        is GlobalSyncState.CheckingNearby -> {
            LedgerSyncIndicator(progress = null)
            Text(
                text = stringResource(R.string.hive_ledger_checking_nearby),
                style = MaterialTheme.typography.labelLarge,
                color = colors.inkSecondary,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        is GlobalSyncState.Syncing -> {
            LedgerSyncIndicator(progress = null)
            // The pluralStringResource render-site MUST be consumed by a
            // Composable that has `LocalContext.current`. Rendered via
            // `androidx.compose.ui.res.pluralStringResource` at the row of the
            // text below. For 1+1 it picks `one`; otherwise `other`.
            Text(
                text = pluralStringResource(
                    id = R.plurals.hive_ledger_sync_banner,
                    count = sync.extractionCount,
                    sync.extractionCount,
                    sync.peerCount,
                ),
                style = MaterialTheme.typography.labelLarge,
                color = colors.inkSecondary,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        null -> Unit
    }

    // S4/S5/S6 — at most one banner (banner-priority). The ViewModel resolves
    // precedence; we render whatever is current.
    state.banner?.let { banner ->
        LedgerBanner(
            banner = banner,
            onSecondaryAction = onOpenSettings,
        )
    }

    // S2/S6 — list of rows with hairline rules between them.
    LazyColumn(modifier = Modifier.fillMaxSize().background(colors.surfaceCanvas)) {
        items(state.rows, key = { it.id }) { row ->
            LedgerRow(
                extraction = row,
                onResumeCrashed = { onResumeCrashed(row.id) },
                onDiscardCrashed = { onDiscardCrashed(row.id) },
            )
            LedgerRule()
        }
    }
}

