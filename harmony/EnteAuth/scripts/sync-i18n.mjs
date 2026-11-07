// 构建前一键同步官方文案（供 entry/hvigorfile.ts 的 SyncI18n 任务与手动调用）
// 用法：node scripts/sync-i18n.mjs [ente仓库根目录]
//   默认 ente 仓库根目录：<本工程>/../../src/ente（可用环境变量 ENTE_ROOT 覆盖）
// 行为：
//   - ente 仓库不存在 → 打印提示并正常退出（跳过，不阻塞构建）
//   - 依序执行 sync-official-i18n.mjs（刷新 arb 词条）与 sync-web-i18n.mjs（刷新 web 词条）
//     两个脚本仅在内容变化时写盘，可安全地挂到每次构建
//   - 最后运行 audit-i18n.mjs：有缺失词条时打印清单提醒（新代码 tr() 尚未翻译），
//     不影响退出码；脚本本身异常也不阻塞（仅告警）
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const enteRoot = resolve(
  process.argv[2] ?? process.env.ENTE_ROOT ?? join(projectRoot, '..', '..', 'src', 'ente'),
);
const arbDir = join(enteRoot, 'mobile', 'packages', 'strings', 'lib', 'l10n', 'arb');
const webDir = join(enteRoot, 'web', 'packages', 'base', 'locales');

if (!existsSync(arbDir) && !existsSync(webDir)) {
  console.log('[sync-i18n] 未找到 ente 仓库: ' + enteRoot + '，跳过官方文案同步');
  process.exit(0);
}

const run = (script) => {
  const r = spawnSync(process.execPath, [join(projectRoot, 'scripts', script)], { stdio: 'inherit' });
  if (r.status !== 0) {
    console.error('[sync-i18n] ' + script + ' 执行失败 (exit ' + r.status + ')');
    process.exit(r.status ?? 1);
  }
};

run('sync-official-i18n.mjs');
run('sync-web-i18n.mjs');

// 审计仅提示缺失（新写的 tr() 还没翻译时回退原文，属正常开发态），不阻塞构建
const audit = spawnSync(process.execPath, [join(projectRoot, 'scripts', 'audit-i18n.mjs')], {
  stdio: ['ignore', 'pipe', 'inherit'],
  encoding: 'utf8',
});
if (audit.status === 0) {
  console.log('[sync-i18n] 审计通过，无缺失词条');
} else if (audit.stdout) {
  const lines = audit.stdout.split('\n');
  const missIdx = lines.findIndex((l) => l.includes('缺失'));
  console.warn('[sync-i18n] 存在未翻译词条（其他语言将回退中文原文）：');
  for (const l of (missIdx >= 0 ? lines.slice(missIdx, missIdx + 40) : lines)) {
    if (l.trim().length > 0) console.warn('  ' + l);
  }
} else {
  console.warn('[sync-i18n] audit-i18n.mjs 执行异常，忽略（不阻塞构建）');
}
