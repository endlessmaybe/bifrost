import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const read = async (relative) => readFile(new URL(relative, root), 'utf8');

test('Windows UI is service-health driven and uses DPAPI protected UI state', async () => {
  const ui = await read('windows-app/UiShellViewModel.cs');
  const bridge = await read('windows-app/MainWindow.xaml.cs');
  const xaml = await read('windows-app/MainWindow.xaml');
  const store = await read('windows-app/UiStateStore.cs');
  for (const marker of [
    'IUiShellCoordinator', 'DisconnectAsync(', 'ApplyStatus(',
    'UiPresentationReducer.FromServiceStatus', 'PrepareSignedPackageAsync(',
    'StageConfigAsync(', 'ConnectAsync(', 'Persist(',
    '"mode"', '"core"', '"source"', '"country"', '"front_source"',
    '"app_policy"', '"include_apps"', '"exclude_apps"', '"theme"',
    'StatusText',
  ]) assert.ok(ui.includes(marker), `missing ${marker}`);
  for (const marker of [
    'ProtectedData.Protect', 'ProtectedData.Unprotect', 'Flush(true)',
    'BF-UI-STATE-CORRUPT', 'BF-UI-STATE-WRITE', 'BF-UI-STATE-MIGRATION',
    'LegacyJsonName', 'LegacyThemeName', 'ReadLegacyState', 'DeleteLegacyFiles',
    '_deleteFile', 'TryGetAttributes',
  ]) {
    assert.ok(store.includes(marker), `missing protected storage marker ${marker}`);
  }
  assert.doesNotMatch(bridge, /LocalAppData|ui-state\.json|theme\.txt|File\.(Read|Write)AllText/);
  assert.doesNotMatch(ui, /閽熸€?/);
  assert.match(xaml, /StatusLamp.*StatusLampStyle/);
  assert.match(xaml, /Command="\{Binding ConnectCommand\}"/);
  assert.match(xaml, /Command="\{Binding NavigateCommand\}"/);
});

test('Android UI persists policy through the encrypted store and removes the retired style selection', async () => {
  const activity = await read('android-app/src/main/java/com/bifrost/client/MainActivity.kt');
  const text = await read('android-app/src/main/java/com/bifrost/client/ui/model/BifrostUiText.kt');
  for (const marker of [
    'BifrostSecureStore.UiKeys', 'BifrostSecureStore.migrateLegacyPreferences',
    'BifrostSecureStore.get', 'BifrostSecureStore.putBatch', '"mode"', '"core"', '"source"',
    '"country"', '"front_source"', '"app_policy"', '"app_policy_enabled"', '"include_apps"',
    '"exclude_apps"', '"theme"', 'stopVpnService()', 'BifrostUiText.disconnectingTunnel',
  ]) assert.ok(activity.includes(marker), `missing ${marker}`);
  assert.match(text, /disconnectingTunnel/);
  assert.doesNotMatch(activity, /getSharedPreferences\(["']bifrost-ui["']/);
  assert.match(activity, /appPolicy.*allow.*exclude/s);
  assert.match(activity, /"theme" to null, "design_direction" to null/);
  const screen = await read('android-app/src/main/java/com/bifrost/client/ui/screens/BifrostAHomeScreen.kt');
  const theme = await read('android-app/src/main/java/com/bifrost/client/ui/theme/BifrostTheme.kt');
  assert.doesNotMatch(screen, /DesignDirectionSelector|onThemeChanged|onDesignDirectionChanged|initialTheme/);
  assert.doesNotMatch(theme, /BifrostDesignDirection|LightColors|SpatialTokens|SignalTokens/);
  assert.match(screen, /BifrostSettingsScreen\(/);
});

test('Windows recovery activation uses the same enrollment contract as Android without an account-ID prerequisite', async () => {
  const bridge = await read('windows-app/MainWindow.xaml.cs');
  const handler = bridge.slice(bridge.indexOf('private async void Recover_Click'), bridge.indexOf('private async void RotateRecoveryCode_Click'));
  assert.match(handler, /EnrollCommand\.ExecuteAsync/);
  assert.doesNotMatch(handler, /RecoverCommand|RecoveryPublicIdBox/);
  const android = await read('android-app/src/main/java/com/bifrost/client/BifrostControlClient.kt');
  assert.match(android, /fun recover\(baseUrl: String, recoveryCode: String\)/);
  assert.match(android, /enroll\(baseUrl, recoveryCode\)/);
});
