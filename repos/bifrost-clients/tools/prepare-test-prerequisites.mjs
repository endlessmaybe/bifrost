import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');
const workspace = path.resolve(repo, '..', '..');
const executable = name => process.platform === 'win32' ? `${name}.exe` : name;
const dotnet = process.env.BIFROST_DOTNET?.trim()
  || path.join(workspace, 'build-work', 'toolchains', 'dotnet', executable('dotnet'));
const gradleWrapper = path.join(repo, 'android-app', process.platform === 'win32' ? 'gradlew.bat' : 'gradlew');
const gradleWrapperJar = path.join(repo, 'android-app', 'gradle', 'wrapper', 'gradle-wrapper.jar');
const gradle = process.platform === 'win32'
  ? (process.env.JAVA_HOME?.trim() ? path.join(process.env.JAVA_HOME.trim(), 'bin', 'java.exe') : 'java.exe')
  : gradleWrapper;
const gradlePrefix = process.platform === 'win32'
  ? ['-Xmx64m', '-Xms64m', '-Dorg.gradle.appname=gradlew', '-classpath', gradleWrapperJar, 'org.gradle.wrapper.GradleWrapperMain']
  : [];

function run(command, args, cwd, timeout, attempts = 1) {
  let result;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    result = spawnSync(command, args, {
      cwd,
      encoding: 'utf8',
      timeout,
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (result.status === 0) return;
  }
  const detail = `${result?.stdout ?? ''}${result?.stderr ?? ''}`.trim();
  const processState = `status=${result?.status ?? 'null'} signal=${result?.signal ?? 'none'} error=${result?.error?.message ?? 'none'}`;
  throw new Error(`test prerequisite failed after ${attempts} attempt(s) (${path.basename(command)} ${args.join(' ')}; ${processState}):\n${detail}`);
}

if (!fs.existsSync(dotnet)) throw new Error(`locked .NET toolchain missing: ${dotnet}`);
if (!fs.existsSync(gradleWrapper) || !fs.existsSync(gradleWrapperJar)) throw new Error(`Android Gradle wrapper missing: ${gradleWrapper}`);
if (path.isAbsolute(gradle) && !fs.existsSync(gradle)) throw new Error(`Java runtime missing: ${gradle}`);

const projects = [
  'windows-app/BifrostApp.csproj',
  'windows-service/BifrostClientService.csproj',
  'tests/Ed25519Probe/Ed25519Probe.csproj',
  'tests/MihomoCompilerFixture/MihomoCompilerFixture.csproj',
  'tests/MihomoControllerFixture/MihomoControllerFixture.csproj',
  'tests/MihomoHandoverFixture/MihomoHandoverFixture.csproj',
  'tests/MihomoHealthProbeFixture/MihomoHealthProbeFixture.csproj',
  'tests/MihomoRuntimeFixture/MihomoRuntimeFixture.csproj',
  'tests/RuntimePerformanceFixture/RuntimePerformanceFixture.csproj',
  'tests/ui-render/BifrostUiRender.csproj',
  'tests/ui-state-fixture/BifrostUiStateFixture.csproj',
  'tests/windows-probe-fixture/BifrostProbeFixture.csproj',
  'tests/windows-service-contract-fixture/windows-service-contract-fixture.csproj',
];

const projectPaths = [
  ...projects.map(relativeProject => path.join(repo, ...relativeProject.split('/'))),
  path.join(workspace, 'repos', 'bifrost-infra', 'installer', 'BifrostSetup.csproj'),
];

for (const project of projectPaths) {
  const assets = path.join(path.dirname(project), 'obj', 'project.assets.json');
  if (!fs.existsSync(assets)) run(dotnet, ['restore', project, '--nologo'], repo, 120_000);
}

const androidOutputs = [
  path.join(repo, 'android-app', 'build', 'tmp', 'kotlin-classes', 'debug', 'com', 'bifrost', 'client', 'ui', 'model', 'BifrostAndroidLayoutPolicy.class'),
  path.join(repo, 'android-app', 'build', 'intermediates', 'javac', 'debug', 'compileDebugJavaWithJavac', 'classes', 'com', 'bifrost', 'client', 'BifrostApplicationPolicySnapshot.class'),
  path.join(repo, 'android-app', 'build', 'intermediates', 'javac', 'debug', 'compileDebugJavaWithJavac', 'classes', 'com', 'bifrost', 'client', 'BifrostApplicationPolicyConnectionCoordinator.class'),
];

if (androidOutputs.some(output => !fs.existsSync(output))) {
  // Gradle's single-use daemon can occasionally lose its first startup while
  // Windows is scanning a freshly recreated build tree. One bounded retry is
  // safe because these compile tasks are deterministic and local/offline.
  run(gradle, [...gradlePrefix, '--offline', '--no-daemon', '--console=plain', 'compileDebugKotlin', 'compileDebugJavaWithJavac'], path.dirname(gradleWrapper), 300_000, 2);
}

for (const output of androidOutputs) {
  if (!fs.existsSync(output)) throw new Error(`test prerequisite output missing after locked offline build: ${output}`);
}
