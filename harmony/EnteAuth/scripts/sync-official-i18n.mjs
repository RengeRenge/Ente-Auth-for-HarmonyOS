// 从 ente 官方 mobile arb 翻译刷新 rawfile/i18n/official.json（自建词条在 custom.json，不受影响）
// 用法：
//   node scripts/sync-official-i18n.mjs [ente仓库根目录]        刷新已有词条的翻译
//   node scripts/sync-official-i18n.mjs --add "中文词条" [...]  追加官方词条并刷新全部翻译
//   默认 ente 仓库根目录：<本工程>/../../src/ente
//
// 注意：当前 official.json 是历史快照，少数词条（如“备注”“已添加”）来源于
// ente web 翻译或旧版 arb，与当前 mobile arb 措辞不同。运行本脚本会把所有
// 词条统一对齐到当前 mobile arb（scripts/official-arb-keys.json 记录每个词条
// 选择的 arb 键，保证多次运行结果一致）。如只想微调个别词条，请手工编辑。
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const addIdx = args.indexOf('--add');
let addKeys = [];
let enteArg;
if (addIdx >= 0) {
  addKeys = args.slice(addIdx + 1).filter((k) => k.length > 0);
  enteArg = args.slice(0, addIdx).find((a) => !a.startsWith('--'));
} else {
  enteArg = args.find((a) => !a.startsWith('--'));
}
const enteRoot = resolve(enteArg ?? join(projectRoot, '..', '..', 'src', 'ente'));
const arbDir = join(enteRoot, 'mobile', 'packages', 'strings', 'lib', 'l10n', 'arb');
const outFile = join(projectRoot, 'entry', 'src', 'main', 'resources', 'rawfile', 'i18n', 'official.json');
// 中文词条 -> arb 键的持久映射，避免中文值多义时每次同步选键漂移
const keyMapFile = join(projectRoot, 'scripts', 'official-arb-keys.json');
// web 来源词条（scripts/official-web-keys.json）由 sync-web-i18n.mjs 独占管理，本脚本跳过
const webKeyMapFile = join(projectRoot, 'scripts', 'official-web-keys.json');

// 与 Index.ets 中 LOCALE_CODES 保持一致
const LOCALES = [
  'ar', 'bg', 'ca', 'cs', 'de', 'el', 'en', 'es', 'fa', 'fr', 'he', 'hu',
  'id', 'it', 'ja', 'ko', 'lt', 'nl', 'pl', 'pt_BR', 'ro', 'ru', 'sl', 'sk',
  'tr', 'uk', 'vi', 'zh_CN', 'zh_TW',
];

const parseLoose = (p) => JSON.parse(readFileSync(p, 'utf8').replace(/,\s*([}\]])/g, '$1'));
const stripMeta = (arb) => {
  const out = new Map();
  for (const [k, v] of Object.entries(arb)) {
    if (!k.startsWith('@')) out.set(k, v);
  }
  return out;
};

if (!existsSync(arbDir)) {
  console.error('找不到 arb 目录: ' + arbDir);
  process.exit(1);
}

const arbByLocale = new Map();
for (const code of LOCALES) {
  const p = join(arbDir, 'strings_' + code + '.arb');
  arbByLocale.set(code, existsSync(p) ? stripMeta(parseLoose(p)) : new Map());
}
const enMap = arbByLocale.get('en');

// 候选：zh_CN 值 == 词条 的所有 arb 键；不足时再补 en 值 == 词条 的键
const candidatesByKey = new Map();
for (const [k, v] of arbByLocale.get('zh_CN')) {
  if (!candidatesByKey.has(v)) candidatesByKey.set(v, []);
  candidatesByKey.get(v).push(k);
}
for (const [k, v] of enMap) {
  if (!candidatesByKey.has(v)) candidatesByKey.set(v, []);
  candidatesByKey.get(v).push(k);
}

// 从 arb 键生成词条：缺失语种用英文值兜底（与既有转换保持一致）
const buildEntry = (arbKey) => {
  const en = enMap.get(arbKey);
  const per = {};
  for (const code of LOCALES) {
    const v = arbByLocale.get(code).get(arbKey);
    if (v !== undefined && v.length > 0) {
      per[code] = v;
    } else if (en !== undefined && en.length > 0) {
      per[code] = en;
    }
  }
  return per;
};

// 打分：候选键生成的词条与旧词条逐语种比对，取吻合最多者；全新词条取翻译最完整者
const pickArbKey = (srcKey, old) => {
  const cands = candidatesByKey.get(srcKey);
  if (cands === undefined || cands.length === 0) return undefined;
  let best = undefined;
  let bestScore = -1;
  for (const cand of cands) {
    const entry = buildEntry(cand);
    let score = 0;
    if (old !== undefined) {
      for (const [loc, v] of Object.entries(old)) {
        if (entry[loc] === v) score++;
      }
    } else {
      let real = 0;
      for (const [loc, v] of Object.entries(entry)) {
        if (loc === 'en') continue;
        const en = enMap.get(cand);
        if (en === undefined || v !== en) real++;
      }
      score = real;
    }
    if (score > bestScore) {
      bestScore = score;
      best = cand;
    }
  }
  return best;
};

const keyMap = existsSync(keyMapFile) ? parseLoose(keyMapFile) : {};
const webManaged = existsSync(webKeyMapFile)
  ? new Set(Object.keys(parseLoose(webKeyMapFile)))
  : new Set();
const prev = existsSync(outFile) ? parseLoose(outFile) : {};
for (const k of addKeys) {
  if (!(k in prev)) prev[k] = {};
}

const out = {};
const newKeyMap = {};
let missing = 0;
for (const srcKey of Object.keys(prev)) {
  if (webManaged.has(srcKey)) {
    out[srcKey] = prev[srcKey]; // web 来源词条原样保留，由 sync-web-i18n.mjs 管理
    continue;
  }
  let arbKey = keyMap[srcKey];
  if (arbKey !== undefined && !enMap.has(arbKey) && !arbByLocale.get('zh_CN').has(arbKey)) {
    arbKey = undefined; // 上游键已改名，重新解析
  }
  if (arbKey === undefined) {
    arbKey = pickArbKey(srcKey, prev[srcKey]);
  }
  if (arbKey === undefined) {
    console.warn('警告: 官方 arb 中未找到词条 "' + srcKey + '"，保留原值');
    out[srcKey] = prev[srcKey];
    missing++;
    continue;
  }
  newKeyMap[srcKey] = arbKey;
  out[srcKey] = buildEntry(arbKey);
}

// 仅在内容变化时写盘：避免构建钩子每次运行都改动 mtime，破坏增量构建
const writeIfChanged = (file, content) => {
  if (!existsSync(file) || readFileSync(file, 'utf8') !== content) {
    writeFileSync(file, content, 'utf8');
  }
};
writeIfChanged(outFile, JSON.stringify(out, null, 2));
writeIfChanged(keyMapFile, JSON.stringify(newKeyMap, null, 2));
if (addKeys.length > 0) {
  console.log('已尝试追加词条: ' + addKeys.join('、'));
}
console.log('official.json 已更新: ' + Object.keys(out).length + ' 条（未匹配 ' + missing + ' 条，已保留原值）');
console.log('自建文案请直接编辑 custom.json（键为中文原文，值可只含用到的语言）');
