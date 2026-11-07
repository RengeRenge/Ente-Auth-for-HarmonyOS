// i18n 覆盖审计：扫描全部 .ets 源码中的 tr()/icuPlural() 字面量键，
// 检查是否存在于 official.json 或 custom.json；缺失则其他语言会回退中文
// 用法：node scripts/audit-i18n.mjs
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(projectRoot, 'entry', 'src', 'main', 'ets');
const i18nDir = join(projectRoot, 'entry', 'src', 'main', 'resources', 'rawfile', 'i18n');

const parseLoose = (p) => JSON.parse(readFileSync(p, 'utf8').replace(/,\s*([}\]])/g, '$1'));
const official = parseLoose(join(i18nDir, 'official.json'));
const custom = parseLoose(join(i18nDir, 'custom.json'));

const etsFiles = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      walk(p);
    } else if (name.endsWith('.ets')) {
      etsFiles.push(p);
    }
  }
};
walk(srcDir);

const usage = new Map(); // key -> [{file, line}]
const scan = (p) => {
  const lines = readFileSync(p, 'utf8').split('\n');
  lines.forEach((line, i) => {
    const re = /\b(?:this\.)?tr\('((?:[^'\\]|\\.)*)'/g;
    let m;
    while ((m = re.exec(line)) !== null) {
      const key = m[1].replace(/\\n/g, '\n').replace(/\\'/g, "'").replace(/\\\\/g, '\\');
      if (!usage.has(key)) usage.set(key, []);
      usage.get(key).push(p + ':' + (i + 1));
    }
  });
};
etsFiles.forEach(scan);

const missing = [];
const customOnly = [];
for (const [key, refs] of usage) {
  const inOfficial = key in official;
  const inCustom = key in custom;
  if (!inOfficial && !inCustom) {
    missing.push({ key, refs });
  } else if (!inOfficial) {
    customOnly.push({ key, refs });
  }
}

console.log('扫描 ' + etsFiles.length + ' 个 .ets，tr() 字面量 ' + usage.size + ' 个');
console.log('缺失（official 与 custom 均无）: ' + missing.length);
for (const m of missing) {
  console.log('  MISS ' + JSON.stringify(m.key));
  for (const r of m.refs) {
    console.log('       ' + r);
  }
}
console.log('仅 custom：' + customOnly.length);
for (const m of customOnly) {
  console.log('  CUSTOM ' + JSON.stringify(m.key) + '  <- ' + m.refs[0]);
}
// 反向：official+custom 中已无代码引用的键（供清理参考）
const allKeys = [...Object.keys(official), ...Object.keys(custom)];
const unused = allKeys.filter((k) => !usage.has(k));
console.log('未被 tr() 引用的键: ' + unused.length + '（含 @-键/动态键/文案遗留，仅供参考）');

// 语种覆盖检查：official/custom 中的键若缺任一语种，该语言运行时将回退中文原文
const LOCALES = [
  'ar', 'bg', 'ca', 'cs', 'de', 'el', 'en', 'es', 'fa', 'fr', 'he', 'hu',
  'id', 'it', 'ja', 'ko', 'lt', 'nl', 'pl', 'pt_BR', 'ro', 'ru', 'sl', 'sk',
  'tr', 'uk', 'vi', 'zh_CN', 'zh_TW',
];
let partial = 0;
for (const [src, data] of [['official', official], ['custom', custom]]) {
  for (const [k, v] of Object.entries(data)) {
    if (k.startsWith('@')) continue;
    const miss = LOCALES.filter((l) => typeof v[l] !== 'string' || v[l].length === 0);
    if (miss.length > 0) {
      partial++;
      console.log('  PARTIAL(' + src + ') ' + JSON.stringify(k) + ' 缺语种: ' + miss.join(','));
    }
  }
}
console.log('语种覆盖不全的键: ' + partial + '（缺失语种回退中文）');
if (partial > 0) {
  process.exitCode = 1;
}
if (missing.length > 0) {
  process.exitCode = 1;
}
