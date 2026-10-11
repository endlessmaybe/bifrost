import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const androidSource = path.join(root, 'android-app', 'src', 'main', 'java');
const catalog = path.join(androidSource, 'com', 'bifrost', 'client', 'ui', 'model', 'BifrostUiText.kt');
const generatedErrorCatalog = path.join(androidSource, 'com', 'bifrost', 'client', 'BifrostErrorRegistry.kt');
const han = /[\u4e00-\u9fff]/u;
const mojibake = /(?:\uFFFD|ï¿½|Ã.|Â.|â.|锟斤拷)/u;
// Kotlin string interpolation legitimately closes with `}}`; detect only
// literal template openings and printf-style placeholders in production text.
const placeholder = /(?:\{\{|%[a-zA-Z])/u;

function filesUnder(directory) {
  const result = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...filesUnder(file));
    else if (/\.(kt|java)$/u.test(entry.name)) result.push(file);
  }
  return result;
}

test('Android production user-visible text is centralized and encoding-clean', () => {
  const sources = filesUnder(androidSource);
  for (const file of sources) {
    const text = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(text, mojibake, `mojibake/replacement character in ${path.relative(root, file)}`);
    assert.doesNotMatch(text, placeholder, `unregistered format placeholder in ${path.relative(root, file)}`);
    if (![catalog, generatedErrorCatalog].some((allowed) => path.resolve(file) === path.resolve(allowed))) {
      assert.doesNotMatch(text, han, `unregistered Han literal in ${path.relative(root, file)}`);
    }
  }
  const catalogText = fs.readFileSync(catalog, 'utf8');
  assert.match(catalogText, han);
  assert.doesNotMatch(catalogText, mojibake);
  assert.doesNotMatch(catalogText, placeholder, 'catalog contains an unregistered format placeholder');
  assert.match(catalogText, /fun\s+connectionStatus/);
});

test('catalog scan rejects a counterexample outside the audited catalogue', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-text-'));
  const counterexample = path.join(temporary, 'Counterexample.kt');
  try {
    fs.writeFileSync(counterexample, 'const val bad = "\u4e0d应出现在这里"', 'utf8');
    const text = fs.readFileSync(counterexample, 'utf8');
    assert.throws(() => { if (han.test(text)) throw new Error('counterexample rejected'); }, /counterexample rejected/);
  } finally {
    fs.rmSync(counterexample, { force: true });
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test('catalog scan rejects replacement, mojibake, Han and placeholder counterexamples', () => {
  const counterexamples = [
    ['replacement', '\uFFFD'],
    ['mojibake', '锟斤拷'],
    ['unregistered Han', '未登记文本'],
    ['printf placeholder', '%s'],
    ['template placeholder', '{{secret}}'],
  ];
  for (const [label, text] of counterexamples) {
    assert.throws(() => {
      if (mojibake.test(text) || han.test(text) || placeholder.test(text)) throw new Error(`${label} rejected`);
    }, /rejected/, label);
  }
});
