import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('production UI motion is feedback-first, interruptible, and reduced-motion aware', () => {
  const windowCode = read('windows-app/MainWindow.xaml.cs');
  const dial = read('windows-app/ObsidianMechanicalDial.cs');
  const components = read('windows-app/Themes/Components.xaml');
  const androidScreen = read('android-app/src/main/java/com/bifrost/client/ui/screens/BifrostAHomeScreen.kt');

  assert.match(windowCode, /ReduceMotion\s*=>\s*SystemParameters\.HighContrast\s*\|\|\s*!SystemParameters\.ClientAreaAnimation/);
  assert.match(windowCode, /TranslateTransform\(0, 8\)/);
  assert.match(windowCode, /BeginAnimation\(OpacityProperty/);
  assert.match(windowCode, /HandoffBehavior\.SnapshotAndReplace/g);
  assert.match(windowCode, /TimeSpan\.FromMilliseconds\(180\)/);
  assert.match(windowCode, /TimeSpan\.FromMilliseconds\(140\)/);
  assert.doesNotMatch(windowCode, /TimeSpan\.FromMilliseconds\((?:[4-9]\d\d|\d{4,})\)/, 'navigation/status feedback must stay short');

  assert.match(dial, /ShouldAnimate\s*=>\s*!ReduceMotion/);
  assert.match(dial, /CompositionTarget\.Rendering\s*\+=/);
  assert.match(dial, /CompositionTarget\.Rendering\s*-=/);
  assert.match(dial, /HandoffBehavior\.SnapshotAndReplace/);
  assert.match(dial, /opacity-only cross-fade/i);

  // Component templates must not smuggle decorative storyboards or layout-
  // changing size animation back into every ordinary button interaction.
  assert.doesNotMatch(components, /Storyboard|EventTrigger|ThicknessAnimation|WidthAnimation|HeightAnimation/);
  assert.doesNotMatch(components, /ScaleTransform/, 'ordinary controls use static pressed feedback, not bounce/zoom');

  // Telemetry redraws must not animate the size of the whole screen.
  assert.doesNotMatch(androidScreen, /animateContentSize\(\)/);
  assert.doesNotMatch(androidScreen, /rememberInfiniteTransition|infiniteRepeatable/);
});
