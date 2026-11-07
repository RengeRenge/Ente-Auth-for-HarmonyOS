// 从 ente 官方 web 翻译刷新 rawfile/i18n/official.json 中 web 来源的词条
// （scripts/official-web-keys.json 记录 中文词条 -> web 翻译键 的映射）
// 用法：
//   node scripts/sync-web-i18n.mjs [ente仓库根目录]
//   默认 ente 仓库根目录：<本工程>/../../src/ente
//
// 这些词条与 arb 来源词条同存于 official.json；sync-official-i18n.mjs 会跳过
// 本映射中的词条（由本脚本独占管理），避免被 arb 值误覆盖。
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const enteRoot = resolve(process.argv[2] ?? join(projectRoot, '..', '..', 'src', 'ente'));
const webDir = join(enteRoot, 'web', 'packages', 'base', 'locales');
const keyMapFile = join(projectRoot, 'scripts', 'official-web-keys.json');
const outFile = join(projectRoot, 'entry', 'src', 'main', 'resources', 'rawfile', 'i18n', 'official.json');

const parseLoose = (p) => JSON.parse(readFileSync(p, 'utf8').replace(/,\s*([}\]])/g, '$1'));

if (!existsSync(webDir)) {
  console.error('找不到 web 翻译目录: ' + webDir);
  process.exit(1);
}

// 本工程 locale（与 Index.ets LOCALE_CODES 一致） -> web locale 目录名；空串表示 web 无此语言
const WEB_LOCALE = {
  ar: 'ar-SA', bg: 'bg-BG', ca: 'ca-ES', cs: 'cs-CZ', de: 'de-DE', el: 'el-GR',
  en: 'en-US', es: 'es-ES', fa: 'fa-IR', fr: 'fr-FR', he: '', hu: 'hu-HU',
  id: 'id-ID', it: 'it-IT', ja: 'ja-JP', ko: 'ko-KR', lt: 'lt-LT', nl: 'nl-NL',
  pl: 'pl-PL', pt_BR: 'pt-BR', ro: 'ro-RO', ru: 'ru-RU', sl: 'sl-SI', sk: 'sk-SK',
  tr: 'tr-TR', uk: 'uk-UA', vi: 'vi-VN', zh_CN: 'zh-CN', zh_TW: 'zh-TW',
};

const keyMap = parseLoose(keyMapFile);
const official = existsSync(outFile) ? parseLoose(outFile) : {};

const webByLocale = new Map();
for (const code of [...new Set(Object.values(WEB_LOCALE))]) {
  if (!code) continue;
  const p = join(webDir, code, 'translation.json');
  webByLocale.set(code, existsSync(p) ? parseLoose(p) : {});
}
const enWeb = webByLocale.get('en-US');

let missing = 0;
for (const [zhKey, webKey] of Object.entries(keyMap)) {
  const en = enWeb[webKey];
  if (typeof en !== 'string' || en.length === 0) {
    console.warn('警告: web 翻译缺键 "' + webKey + '"，跳过词条 "' + zhKey + '"');
    missing++;
    continue;
  }
  const per = {};
  for (const [loc, webLoc] of Object.entries(WEB_LOCALE)) {
    if (!webLoc) continue; // he 等无对应 web 语言，统一用英文兜底
    const v = webByLocale.get(webLoc)[webKey];
    if (typeof v === 'string' && v.length > 0) per[loc] = v;
  }
  for (const loc of Object.keys(WEB_LOCALE)) {
    if (per[loc] === undefined) per[loc] = en;
  }
  official[zhKey] = per;
}

// 仅在内容变化时写盘：避免构建钩子每次运行都改动 mtime，破坏增量构建
const next = JSON.stringify(official, null, 2);
if (!existsSync(outFile) || readFileSync(outFile, 'utf8') !== next) {
  writeFileSync(outFile, next, 'utf8');
}
console.log('official.json web 词条已更新: ' + Object.keys(keyMap).length + ' 条（缺键 ' + missing + ' 条）');
