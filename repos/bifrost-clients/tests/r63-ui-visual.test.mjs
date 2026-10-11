import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const artifactDir = path.join(root, 'artifacts', 'ui-acceptance', 'nordic-exact-20260820');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

function pngSize(file) {
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a', `${file} is not a PNG`);
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20), bytes };
}

function luminance(hex) {
  const rgb = hex.slice(1).match(/.{2}/g).map(value => Number.parseInt(value, 16) / 255)
    .map(value => value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
}
function contrast(foreground, background) {
  const a = luminance(foreground), b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function validateMeasuredWindows(rows) {
  assert.equal(rows.length, 7);
  const windowsNavigation = rows[0]?.navigation?.order?.includes('activity')
    ? { order: ['home', 'nodes', 'routing', 'activity', 'settings'], labels: ['连接', '线路', '分流', '活动', '设置'] }
    : { order: ['home', 'nodes', 'routing', 'activity', 'settings'], labels: ['连接', '线路', '分流', '活动', '设置'] };
  for (const row of rows) {
    assert.equal(row.measurementSource, 'production-wpf-measure');
    assert.ok(row.physicalViewportPx?.width > 0 && row.physicalViewportPx?.height > 0);
    assert.ok(row.logicalViewportDip?.width > 0 && row.logicalViewportDip?.height > 0);
    assert.ok(Number.isFinite(row.scale) && row.scale > 0);
    assert.equal(row.dpiScale, row.scale);
    assert.equal(row.simulationMethod, 'offscreen-logical-dpi-simulation-with-production-min-size');
    assert.equal(row.physicalMonitorVerification, 'PENDING-EXTERNAL');
    assert.ok(Math.abs(row.logicalViewportDip.width - row.physicalViewportPx.width / row.scale) < 0.01);
    assert.ok(Math.abs(row.logicalViewportDip.height - row.physicalViewportPx.height / row.scale) < 0.01);
    assert.ok(row.arrangedLogicalViewportDip?.width >= row.logicalViewportDip.width);
    assert.ok(row.arrangedLogicalViewportDip?.height >= row.logicalViewportDip.height);
    assert.equal(row.requestedVsArrangedDelta.width, row.arrangedLogicalViewportDip.width - row.logicalViewportDip.width);
    assert.equal(row.requestedVsArrangedDelta.height, row.arrangedLogicalViewportDip.height - row.logicalViewportDip.height);
    assert.equal(row.fitsRequestedLogicalViewport, row.requestedViewportStatus === 'PASS');
    assert.ok(row.rootBounds?.width > 0 && row.rootBounds?.height > 0);
    // The desktop Network Console intentionally uses an outer shell inset at
    // non-narrow widths.  The rendered root must fit inside the arranged
    // viewport; equality is only required when the shell has no inset.
    assert.ok(row.rootBounds.width <= row.arrangedLogicalViewportDip.width + 0.5);
    assert.ok(row.rootBounds.height <= row.arrangedLogicalViewportDip.height + 0.5);
    assert.ok(row.arrangedLogicalViewportDip.width - row.rootBounds.width <= 32);
    assert.ok(row.arrangedLogicalViewportDip.height - row.rootBounds.height <= 32);
    assert.ok(Array.isArray(row.elementMeasurements) && row.elementMeasurements.length >= 15);
    const names = new Set(row.elementMeasurements.map(element => element.name));
    for (const name of ['NavStack', 'ThemeQuickButton', 'ConnectButton', 'ModeBox', 'ChartSurface', 'ThemeBox', 'AppPolicyEnabledBox', 'NavButton:home', 'NavButton:nodes', 'NavButton:routing', 'NavButton:settings', 'ModeItem:smart', 'ModeItem:global', 'ModeItem:smartgate']) assert.ok(names.has(name), `missing measured production element ${name}`);
    // The renderer deliberately treats settings/routing as vertically
    // scrollable surfaces.  Re-derive the strict invariant from its measured
    // public fields: every visible target must stay horizontally reachable;
    // the full-home clipping check remains renderer-owned because page
    // membership is not serialized into evidence.json.
    const visible = row.elementMeasurements.filter(element => element.visible);
    const horizontallyReachable = visible.every(element =>
      element.x >= 0 && element.x + element.width <= row.rootBounds.width + 0.5);
    assert.equal(row.derived.noClipping && horizontallyReachable, row.derived.noClipping);
    assert.equal(row.derived.noOverlap, row.overlapPairs.length === 0);
    const measuredTargets = row.targetSizes.every(target =>
      target.pass === (target.visible !== false && target.width >= target.minWidth && target.height >= target.minHeight));
    assert.equal(row.derived.targetPass, measuredTargets);
    const primary = row.primaryBounds;
    assert.equal(row.derived.primaryPass, primary.arrangedPass === (primary.width >= primary.minWidth && primary.height >= primary.minHeight));
    assert.equal(row.derived.arrangedPass, row.derived.noClipping && row.derived.noOverlap && row.derived.targetPass && row.derived.primaryPass && row.derived.navigationPass);
    assert.equal(row.derived.overallPass, row.derived.arrangedPass && row.fitsRequestedLogicalViewport);
    const shippingDashboardViewport = row.logicalViewportDip.width >= 760 && row.logicalViewportDip.height >= 620;
    if (shippingDashboardViewport) {
      assert.equal(row.derived.arrangedPass, true, `${row.width}x${row.height}@${row.scale} shipping dashboard layout must pass`);
      assert.equal(row.derived.overallPass, true, `${row.width}x${row.height}@${row.scale} shipping dashboard viewport must pass`);
    }
    if (!row.fitsRequestedLogicalViewport) {
      assert.match(row.requestedViewportStatus, /^PENDING-EXTERNAL:does-not-fit-requested-logical-viewport$/);
      assert.equal(row.derived.overallPass, false, 'minimum-size expansion cannot masquerade as requested viewport pass');
    }
    assert.deepEqual(row.navigation.order, windowsNavigation.order);
    assert.deepEqual(row.navigation.labels, windowsNavigation.labels);
    assert.equal(row.derived.navigationPass, row.navigation.pass);
  }
}

const androidPolicySourcePath = path.join(root, 'android-app', 'src', 'main', 'java', 'com', 'bifrost', 'client', 'ui', 'model', 'BifrostAndroidLayoutPolicy.kt');
const androidPolicyClassPath = path.join(root, 'android-app', 'build', 'tmp', 'kotlin-classes', 'debug', 'com', 'bifrost', 'client', 'ui', 'model', 'BifrostAndroidLayoutPolicy.class');
const androidPolicyCombinations = [
  [360, 640, 1], [360, 640, 1.3], [360, 640, 2],
  [412, 915, 1], [412, 915, 1.3], [412, 915, 2],
];

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalPolicyPayload(policy) {
  return JSON.stringify({
    summaryLayout: policy.summaryLayout,
    metricLayout: policy.metricLayout,
    targetMinDp: policy.targetMinDp,
    usesScroll: policy.usesScroll,
    wrapsText: policy.wrapsText,
    navigation: policy.navigation,
    homeModes: policy.homeModes,
  });
}

function currentAndroidPolicyIdentity() {
  assert.ok(fs.existsSync(androidPolicySourcePath), `production Android policy source missing: ${androidPolicySourcePath}`);
  assert.ok(fs.existsSync(androidPolicyClassPath), `compiled Android policy output missing: ${androidPolicyClassPath}`);
  return {
    policyClassName: 'com.bifrost.client.ui.model.BifrostAndroidLayoutPolicy',
    policyClassHash: sha256(fs.readFileSync(androidPolicyClassPath)),
    policySourceHash: sha256(fs.readFileSync(androidPolicySourcePath)),
  };
}

function validateAndroidPolicyRows(rows, exporterIdentity) {
  assert.equal(rows.length, 6);
  assert.equal(exporterIdentity.schemaVersion, 1);
  const isExporterDocument = Object.hasOwn(exporterIdentity, 'rows');
  if (isExporterDocument) {
    assert.deepEqual(Object.keys(exporterIdentity).sort(), ['policyClassHash', 'policyClassName', 'policyPayloadDigest', 'policySourceHash', 'rows', 'schemaVersion'].sort(), 'Android exporter top-level shape drift');
  } else if (Object.hasOwn(exporterIdentity, 'status')) {
    assert.deepEqual(Object.keys(exporterIdentity).sort(), ['measurementSource', 'policyClassHash', 'policyClassName', 'policyPayloadDigest', 'policySourceHash', 'schemaVersion', 'status'].sort(), 'Android exporter identity shape drift');
  }
  const current = currentAndroidPolicyIdentity();
  for (const key of ['policyClassName', 'policyClassHash', 'policySourceHash']) {
    assert.equal(exporterIdentity[key], current[key], `stale Android exporter ${key}`);
    assert.match(exporterIdentity[key], key === 'policyClassName' ? /BifrostAndroidLayoutPolicy/ : /^[0-9a-f]{64}$/);
  }
  assert.match(exporterIdentity.policyPayloadDigest, /^[0-9a-f]{64}$/);
  const combinations = new Set();
  const payloads = [];
  rows.forEach((row, index) => {
    assert.deepEqual(Object.keys(row).sort(), ['fontScale', 'height', 'measurementSource', 'payloadDigest', 'policy', 'policyClassHash', 'policyClassName', 'policySourceHash', 'realMeasured', 'reason', 'status', 'width'].sort(), 'Android exporter row shape drift');
    const [expectedWidth, expectedHeight, expectedScale] = androidPolicyCombinations[index];
    assert.equal(row.width, expectedWidth);
    assert.equal(row.height, expectedHeight);
    assert.equal(row.fontScale, expectedScale);
    assert.equal(row.measurementSource, 'production-policy-exporter');
    assert.equal(row.realMeasured, false, 'real-measured Android evidence cannot claim real measurement');
    assert.equal(row.status, 'PENDING-EXTERNAL');
    combinations.add(`${row.width}x${row.height}@${row.fontScale}`);
    assert.equal(row.policyClassName, exporterIdentity.policyClassName);
    assert.equal(row.policyClassHash, exporterIdentity.policyClassHash);
    assert.equal(row.policySourceHash, exporterIdentity.policySourceHash);
    assert.match(row.payloadDigest, /^[0-9a-f]{64}$/);
    assert.deepEqual(Object.keys(row.policy).sort(), ['homeModes', 'metricLayout', 'navigation', 'summaryLayout', 'targetMinDp', 'usesScroll', 'wrapsText'].sort(), 'Android policy payload shape drift');
    assert.ok(['stacked', 'inline'].includes(row.policy.summaryLayout));
    assert.ok(['two_by_two', 'inline'].includes(row.policy.metricLayout));
    assert.equal(row.policy.targetMinDp, 48);
    assert.equal(typeof row.policy.usesScroll, 'boolean');
    assert.equal(typeof row.policy.wrapsText, 'boolean');
    assert.deepEqual(row.policy.navigation, ['连接', '线路', '分流', '活动', '设置']);
    assert.deepEqual(row.policy.homeModes, ['smart', 'global', 'smartgate']);
    const payload = canonicalPolicyPayload(row.policy);
    assert.equal(row.payloadDigest, sha256(Buffer.from(payload, 'utf8')), 'row policy payload digest mismatch');
    payloads.push(payload);
    assert.equal(Object.hasOwn(row, 'noClipping'), false);
    assert.equal(Object.hasOwn(row, 'noOverlap'), false);
  });
  assert.deepEqual([...combinations].sort(), androidPolicyCombinations.map(([width, height, scale]) => `${width}x${height}@${scale}`).sort());
  assert.equal(exporterIdentity.policyPayloadDigest, sha256(Buffer.from(payloads.join('\n'), 'utf8')), 'six-row policy payload digest mismatch');
}

function loadAndroidExporterArtifact() {
  const exporterPath = path.join(artifactDir, 'android-policy-exporter.json');
  assert.ok(fs.existsSync(exporterPath), `required real Android exporter output missing: ${exporterPath}`);
  const exporter = JSON.parse(fs.readFileSync(exporterPath, 'utf8'));
  assert.equal(exporter.schemaVersion, 1);
  assert.equal(exporter.rows?.length, 6);
  validateAndroidPolicyRows(exporter.rows, exporter);
  return exporter;
}

test('measurement evidence rejects constant green-light fixtures', () => {
  const exporterSource = fs.readFileSync(path.join(root, 'android-app', 'src', 'test', 'java', 'com', 'bifrost', 'client', 'BifrostAndroidLayoutPolicyEvidenceExporter.kt'), 'utf8');
  assert.match(exporterSource, /joinToString\(separator = ",", prefix = "\[", postfix = "\]"\)/, 'Kotlin exporter must use compact JSON arrays');
  assert.doesNotMatch(exporterSource, /joinToString\(prefix = "\[", postfix = "\]"\)/, 'Kotlin default comma-space separator would drift from Node canonical JSON');
  const constantWindow = {
    measurementSource: 'constant',
    rootBounds: { width: 100, height: 100 },
    elementMeasurements: [],
    overlapPairs: [],
    targetSizes: [],
    primaryBounds: { width: 1, height: 1, minWidth: 1, minHeight: 1, pass: true },
    navigation: { order: [], labels: [], pass: true },
    derived: { noClipping: true, noOverlap: true, targetPass: true, primaryPass: true, navigationPass: true },
  };
  assert.throws(() => validateMeasuredWindows(Array.from({ length: 7 }, () => constantWindow)), /production-wpf-measure/);
  const fakeAndroid = {
    measurementSource: 'production-policy-exporter',
    realMeasured: true,
    status: 'PENDING-EXTERNAL',
    width: 360, height: 640, fontScale: 1,
    policyClassName: 'com.bifrost.client.ui.model.BifrostAndroidLayoutPolicy',
    policyClassHash: '0'.repeat(64),
    policy: { targetMinDp: 48, navigation: ['连接', '线路', '分流', '活动', '设置'], homeModes: ['smart', 'global', 'smartgate'] },
  };
  assert.throws(() => validateAndroidPolicyRows(Array.from({ length: 6 }, () => fakeAndroid), {
    schemaVersion: 1, policyClassName: 'com.bifrost.client.ui.model.BifrostAndroidLayoutPolicy',
    policyClassHash: '0'.repeat(64), policySourceHash: '0'.repeat(64), policyPayloadDigest: '0'.repeat(64),
  }), /real-measured|stale Android exporter/);

  const evidence = JSON.parse(fs.readFileSync(path.join(artifactDir, 'evidence.json'), 'utf8'));
  const exporter = loadAndroidExporterArtifact();
  const tamperedWindow = JSON.parse(JSON.stringify(evidence.layoutMatrices.windows[0]));
  tamperedWindow.elementMeasurements[0].x = -1;
  assert.throws(() => validateMeasuredWindows([tamperedWindow, ...evidence.layoutMatrices.windows.slice(1)]), /false|true/);
  const arrangedOnly = JSON.parse(JSON.stringify(evidence.layoutMatrices.windows[0]));
  arrangedOnly.fitsRequestedLogicalViewport = false;
  arrangedOnly.requestedViewportStatus = 'PENDING-EXTERNAL:does-not-fit-requested-logical-viewport';
  arrangedOnly.derived.overallPass = true;
  assert.throws(() => validateMeasuredWindows([arrangedOnly, ...evidence.layoutMatrices.windows.slice(1)]), /minimum-size expansion|overallPass|false/);
  const thresholdDrift = JSON.parse(JSON.stringify(exporter.rows));
  thresholdDrift[0].policy.summaryLayout = thresholdDrift[0].policy.summaryLayout === 'stacked' ? 'inline' : 'stacked';
  assert.throws(() => validateAndroidPolicyRows(thresholdDrift, exporter), /digest/);
  const staleSource = { ...exporter, policySourceHash: '0'.repeat(64) };
  assert.throws(() => validateAndroidPolicyRows(exporter.rows, staleSource), /source hash|policySourceHash/);
  const staleClass = { ...exporter, policyClassHash: 'f'.repeat(64) };
  assert.throws(() => validateAndroidPolicyRows(exporter.rows, staleClass), /class hash|policyClassHash/);
  const staleRowIdentity = JSON.parse(JSON.stringify(exporter.rows));
  staleRowIdentity[0].policyClassHash = 'e'.repeat(64);
  assert.throws(() => validateAndroidPolicyRows(staleRowIdentity, exporter), /class hash|identity|strictly equal/);
});

test('approved obsidian production UI contracts and rendered evidence are strict', () => {
  const xaml = read('windows-app/MainWindow.xaml');
  const code = read('windows-app/MainWindow.xaml.cs');
  const rendererCode = read('tests/ui-render/Program.cs');
  const androidBuild = read('android-app/build.gradle.kts');
  const androidExporterSource = read('android-app/src/test/java/com/bifrost/client/BifrostAndroidLayoutPolicyEvidenceExporter.kt');
  const viewModelCode = read('windows-app/UiShellViewModel.cs');
  const androidScreen = read('android-app/src/main/java/com/bifrost/client/ui/screens/BifrostAHomeScreen.kt');
  const androidModel = read('android-app/src/main/java/com/bifrost/client/ui/model/BifrostUiModel.kt');
  const androidTheme = read('android-app/src/main/java/com/bifrost/client/ui/theme/BifrostTheme.kt');
  const androidComponents = read('android-app/src/main/java/com/bifrost/client/ui/components/BifrostAComponents.kt');
  const androidText = read('android-app/src/main/java/com/bifrost/client/ui/model/BifrostUiText.kt');
  for (const theme of ['LightTheme.xaml', 'DarkTheme.xaml']) {
    const tokens = read(`windows-app/Themes/${theme}`);
    const color = key => tokens.match(new RegExp(`x:Key="${key}"[^#]*#([0-9A-Fa-f]{6})`))?.[1];
    const body = `#${color('TextBrush')}`;
    const canvas = `#${color('WindowBackgroundBrush')}`;
    const muted = `#${color('MutedTextBrush')}`;
    assert.ok(contrast(body, canvas) >= 4.5, `${theme} body contrast`);
    assert.ok(contrast(muted, canvas) >= 4.5, `${theme} muted contrast`);
  }

  assert.match(xaml, /WindowStyle="None"/);
  assert.match(xaml, /ResizeMode="CanResize"/);
  assert.match(xaml, /WindowChrome/);
  assert.match(xaml, /MinWidth="760" MinHeight="620"/);
  assert.doesNotMatch(xaml, /x:Name="CompactHomePage"/);
  assert.doesNotMatch(xaml, /x:Name="CompactNavigationBar"/);
  assert.match(xaml, /x:Name="DesignDirectionBox"/);
  assert.match(code, /ApplyResponsivePageLayouts/);
  assert.match(code, /ApplyDesignDirectionResources/);
  assert.match(code, /HandoffBehavior\.SnapshotAndReplace/);
  assert.match(code, /ReduceMotion/);
  assert.match(xaml, /x:Key="ObsidianNavButton"/);
  assert.doesNotMatch(xaml, /x:Key="TopNavButton"/);
  assert.match(xaml, /x:Name="DesktopTitleBar"/);
  assert.match(xaml, /x:Name="SidebarBorder"/);
  assert.match(xaml, /x:Name="NavStack"/);
  assert.match(xaml, /x:Name="HomeCommandSurface"/);
  assert.match(xaml, /x:Name="HomeRouteConsole"/);
  assert.match(code, /MinimizeWindow_Click/);
  assert.match(code, /MaximizeWindow_Click/);
  assert.match(code, /CloseWindow_Click/);
  for (const [tag, label] of [['home', '连接'], ['nodes', '线路'], ['routing', '分流'], ['activity', '活动'], ['settings', '设置']]) {
    assert.match(xaml, new RegExp(`<Button Tag="${tag}"[^>]*AutomationProperties\\.Name="${label}"`), `missing primary navigation ${tag}`);
  }
  for (const mode of ['智能选线', '全局代理', 'SmartGate']) assert.match(xaml, new RegExp(mode));
  assert.match(rendererCode, /UiCaptureContext\.Active/);
  assert.match(code, /FixtureUiShellCoordinator/);
  assert.match(viewModelCode, /IUiShellCoordinator/);
  assert.match(viewModelCode, /AsyncCommand/);
  assert.match(code, /ApplyPresentationState/);
  assert.match(xaml, /Text="\{Binding DashboardStatusTitle\}"/);
  assert.match(xaml, /Style="\{StaticResource StatusLampStyle\}"/);
  for (const color of ['#FF5F57', '#FEBC2E', '#28C840']) assert.doesNotMatch(xaml, new RegExp(color));
  assert.doesNotMatch(xaml, /ToolbarSegmentContainer/);
  assert.match(xaml, /ThemeQuickButton[\s\S]*Command="\{Binding NavigateCommand\}"[\s\S]*CommandParameter="settings"/);
  // The current desktop names the primary page 连接, matching its accessible
  // navigation label; the historical 总览（连接） heading was removed.
  for (const label of ['BIFROST', '连接', '流量趋势', '连接模式']) assert.match(xaml, new RegExp(`Text="${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`));
  assert.doesNotMatch(xaml, /<local:ObsidianMechanicalDial/);
  assert.match(xaml, /x:Name="HeroAuroraImage"/);
  assert.match(xaml, /Text="\{Binding PrimaryActionLabel\}"/);
  assert.match(xaml, /Text="智能选线"/);
  assert.match(xaml, /Text="全局代理"/);
  assert.match(xaml, /Text="SmartGate"/);
  assert.doesNotMatch(code, /ThemeQuick_Click|Theme_Changed|UiSelection_Changed|UpdateText\.Text/);
  assert.doesNotMatch(xaml, /SelectionChanged="(?:Theme_Changed|UiSelection_Changed)"/);
  assert.match(xaml, /Text="\{Binding ControlOriginStatus\}"/);
  assert.match(xaml, /x:Name="SmartGateAdvancedButton"/);
  assert.match(code, /SmartGateAdvanced_Click/);
  assert.doesNotMatch(`${code}\n${xaml}`, /ControlUrlBox|127\.0\.0\.1:8787|Text="https?:\/\//);
  for (const marker of ['BifrostAHomeScreen', 'BifrostConnectionRing', 'BifrostBottomNavigation']) {
    assert.match(androidScreen, new RegExp(marker));
  }
  for (const mode of ['smart', 'global', 'smartgate']) assert.match(androidModel, new RegExp(mode));
  assert.match(androidScreen, /Switch\(/);
  assert.match(androidScreen, /BifrostUiText\.applicationRouting/);
  assert.match(androidScreen, /presentation\.statusText/);
  assert.match(androidScreen, /BifrostUiText\.overviewTitle/);
  assert.match(androidScreen, /BifrostUiText\.currentConnection/);
  assert.match(androidScreen, /BifrostUiText\.smartGate/);
  assert.match(androidScreen, /LocalBifrostDesign\.current/);
  assert.match(androidScreen, /DesignDirectionSelector/);
  assert.match(androidModel, /designDirection/);
  assert.match(androidTheme, /BifrostDesignDirection/);
  assert.match(androidTheme, /BifrostDesignTokens/);
  assert.doesNotMatch(androidScreen, /BifrostThemeQuickAction/);
  assert.match(androidTheme, /BifrostTheme/);
  assert.match(androidComponents, /fun BifrostModeGlyph/);
  assert.match(androidComponents, /minimumInteractiveComponentSize|48\.dp/);
  assert.match(androidComponents, /val surfaceColor = MaterialTheme\.colorScheme\.surface/);
  // The production ring is a Canvas inside a clickable Box.  Keep the
  // historical guard scoped to that function instead of assuming the old
  // sibling Column layout, so a valid Obsidian ring can evolve without
  // weakening the material assertions below.
  const ringStart = androidComponents.indexOf('fun BifrostConnectionRing');
  const summaryStart = androidComponents.indexOf('fun BifrostSummaryCard', ringStart);
  const ringSource = androidComponents.slice(ringStart, summaryStart < 0 ? undefined : summaryStart);
  const ringCanvas = ringSource.match(/Canvas\([\s\S]*?\r?\n\s*}\r?\n\s*}/)?.[0] ?? '';
  assert.ok(ringCanvas, 'connection ring Canvas body missing');
  assert.match(ringCanvas, /drawCircle\(surfaceColor/);
  assert.doesNotMatch(ringCanvas, /MaterialTheme\.colorScheme/);
  assert.doesNotMatch(androidScreen, /fun\s+BifrostScreen\s*\(/);
  assert.doesNotMatch(read('android-app/src/main/java/com/bifrost/client/MainActivity.kt'), /darkColorScheme\s*\(/);

  const names = [
    'bifrost-windows-dark-idle-actual.png',
    'bifrost-windows-light-idle-actual.png',
    'bifrost-windows-dark-protected-test-actual.png',
    'bifrost-windows-light-protected-test-actual.png',
  ];
  const hashes = new Set();
  for (const name of names) {
    const file = path.join(artifactDir, name);
    assert.ok(fs.existsSync(file), `required rendered evidence missing: ${file}`);
    const { width, height, bytes } = pngSize(file);
    assert.equal(width, 1440, `${name} width`);
    assert.equal(height, 810, `${name} height`);
    assert.ok(bytes.length > 50_000, `${name} is implausibly small`);
    assert.doesNotMatch(bytes.toString('latin1'), /tEXt|iTXt|zTXt/, `${name} must not carry text metadata`);
    hashes.add(crypto.createHash('sha256').update(bytes).digest('hex'));
  }
  assert.equal(hashes.size, names.length, 'all four Windows states must render distinctly');

  const evidenceFile = path.join(artifactDir, 'evidence.json');
  assert.ok(fs.existsSync(evidenceFile), 'renderer evidence.json missing');
  const evidenceText = fs.readFileSync(evidenceFile, 'utf8');
  assert.doesNotMatch(evidenceText, /invite|recovery|pairing|session_token|socks_password/i);
  const evidence = JSON.parse(evidenceText);
  const variants = [
    ['bifrost-windows-dark-direct-manual-actual.png', 'direct-manual', 'dark'],
    ['bifrost-windows-light-direct-manual-actual.png', 'direct-manual', 'light'],
    ['bifrost-windows-dark-smartgate-collapsed-actual.png', 'smartgate-collapsed', 'dark'],
    ['bifrost-windows-light-smartgate-collapsed-actual.png', 'smartgate-collapsed', 'light'],
    ['bifrost-windows-dark-smartgate-advanced-actual.png', 'smartgate-advanced', 'dark'],
    ['bifrost-windows-light-smartgate-advanced-actual.png', 'smartgate-advanced', 'light'],
  ];
  assert.ok(Array.isArray(evidence.windowsVariants), 'R25 control-state evidence missing');
  assert.equal(evidence.windowsVariants.length, variants.length);
  const variantHashes = new Set();
  for (const [name, variant, theme] of variants) {
    const file = path.join(artifactDir, name);
    assert.ok(fs.existsSync(file), `required R25 control evidence missing: ${file}`);
    const { width, height, bytes } = pngSize(file);
    assert.equal(width, 1180, `${name} width`);
    assert.equal(height, 760, `${name} height`);
    assert.ok(bytes.length > 20_000, `${name} is implausibly small`);
    assert.doesNotMatch(bytes.toString('latin1'), /tEXt|iTXt|zTXt/, `${name} must not carry text metadata`);
    variantHashes.add(crypto.createHash('sha256').update(bytes).digest('hex'));
    const evidenceRow = evidence.windowsVariants.find(row => row.name === name);
    assert.ok(evidenceRow, `${name} missing from evidence`);
    assert.equal(evidenceRow.variant, variant);
    assert.equal(evidenceRow.theme, theme);
    assert.match(evidenceRow.testFixtureProvenance, /TEST-only|zero-I\/O/i);
    assert.equal(evidenceRow.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
  }
  assert.equal(variantHashes.size, variants.length, 'R25 control states must render distinctly');
  assert.ok(Array.isArray(evidence.windowsDirections), 'A/B/C direction evidence missing');
  assert.equal(evidence.windowsDirections.length, 3);
  const directionHashes = new Set();
  for (const direction of ['a', 'b', 'c']) {
    const row = evidence.windowsDirections.find(item => item.direction === direction);
    assert.ok(row, `direction ${direction} evidence missing`);
    const file = path.join(artifactDir, row.name);
    assert.ok(fs.existsSync(file), `direction ${direction} rendered evidence missing`);
    const { width, height, bytes } = pngSize(file);
    assert.equal(width, 1180);
    assert.equal(height, 760);
    assert.ok(bytes.length > 20_000);
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(row.sha256, digest);
    directionHashes.add(digest);
  }
  assert.equal(directionHashes.size, 3, 'A/B/C directions must produce structurally distinct renders');
  assert.equal(evidence.viewport.width, 1440);
  assert.equal(evidence.viewport.height, 810);
  assert.equal(evidence.windows.length, 4);
  assert.equal(evidence.android.status, 'PENDING-EXTERNAL');
  assert.equal(evidence.android.images.length, 4);
  for (const image of evidence.android.images) {
    assert.equal(image.status, 'PENDING-EXTERNAL');
    assert.match(image.name, /^bifrost-android-(dark|light)-(idle|protected-test)-actual\.png$/);
    assert.match(image.reason, /renderer|emulator|system image/i);
  }
  validateMeasuredWindows(evidence.layoutMatrices.windows);
  const exporter = loadAndroidExporterArtifact();
  assert.deepEqual(evidence.layoutMatrices.androidPolicyExporter, {
    schemaVersion: exporter.schemaVersion,
    status: 'production-policy-exporter',
    measurementSource: 'production-policy-exporter',
    policyClassName: exporter.policyClassName,
    policyClassHash: exporter.policyClassHash,
    policySourceHash: exporter.policySourceHash,
    policyPayloadDigest: exporter.policyPayloadDigest,
  });
  validateAndroidPolicyRows(evidence.layoutMatrices.android, evidence.layoutMatrices.androidPolicyExporter);
  assert.match(androidScreen, /BifrostUiState/);
  assert.match(androidScreen, /SettingsContent\(uiState\.theme/);
  assert.match(androidScreen, /BifrostAndroidLayoutPolicy/);
  assert.match(androidScreen, /height\(48\.dp\)/);
  assert.doesNotMatch(androidScreen, /remember\s*\{\s*mutableStateOf\(initial/);
  assert.match(androidModel, /BifrostRuntimeSignal/);
  assert.match(androidModel, /expectedBindings/);
  const androidPolicy = read('android-app/src/main/java/com/bifrost/client/ui/model/BifrostAndroidLayoutPolicy.kt');
  assert.match(androidPolicy, /production Compose screen/);
  assert.doesNotMatch(androidPolicy, /heightDp\s*:\s*Int\s*=\s*640/);
  const androidScreenBody = androidScreen.slice(androidScreen.indexOf('fun BifrostAHomeScreen'));
  assert.match(androidScreenBody, /BoxWithConstraints[\s\S]*forViewport\(maxWidth\.value, maxHeight\.value, LocalDensity\.current\.fontScale\)/);
  assert.doesNotMatch(androidScreenBody, /maxHeight\.value\.toInt\(\)/);
  assert.doesNotMatch(androidScreenBody, /verticalScroll[\s\S]*BoxWithConstraints/);
  assert.match(read('android-app/src/test/java/com/bifrost/client/BifrostAndroidLayoutPolicyTest.kt'), /360/);
  const renderer = read('tests/ui-render/Program.cs');
  assert.match(renderer, /MeasureWindows/);
  assert.match(renderer, /physicalViewportPx/);
  assert.match(renderer, /logicalViewportDip/);
  assert.match(renderer, /elementMeasurements/);
  assert.match(renderer, /measurementSource/);
  assert.match(renderer, /fitsRequestedLogicalViewport/);
  assert.match(renderer, /requestedVsArrangedDelta/);
  assert.match(renderer, /android-policy-exporter\.json/);
  assert.match(androidBuild, /configurations\.getByName\("debugUnitTestRuntimeClasspath"\)/);
  assert.doesNotMatch(androidBuild, /configurations\.getByName\("testDebugRuntimeClasspath"\)/);
  assert.doesNotMatch(renderer, /width < 420 \|\| fontScale >= 1\.8/);
  assert.doesNotMatch(androidScreen, /\uFFFD/);
  assert.match(read('android-app/src/main/java/com/bifrost/client/ui/model/BifrostUiText.kt'), /connectionCenter/);
  assert.match(androidText, /applicationRouting/);
  assert.match(androidExporterSource, /forWidth\(width, fontScale, height\)/);
  assert.match(androidExporterSource, /joinToString\(separator = ",", prefix = "\[", postfix = "\]"\)/);
  assert.doesNotMatch(androidExporterSource, /private fun number\(/);
  assert.doesNotMatch(read('android-app/src/main/java/com/bifrost/client/BifrostVpnService.kt'), /scheduleAtFixedRate/);
  console.warn('PENDING-EXTERNAL: Android actual Compose renderer unavailable in the locked offline sandbox; no substitute PNGs are accepted.');
});
