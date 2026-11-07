import { hapTasks, OhosPluginId, OhosHapContext, Target } from '@ohos/hvigor-ohos-plugin';
import { getNode, hvigor, HvigorNode } from '@ohos/hvigor';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';

// 构建前自动同步官方文案（官方 arb/web 翻译 -> rawfile/i18n/official.json）：
// 逻辑在 scripts/sync-i18n.mjs；ente 仓库不存在时脚本自行跳过，
// 同步失败仅告警不阻塞构建；脚本仅在内容变化时写盘，不影响增量构建。
hvigor.nodesEvaluated(() => {
  const node: HvigorNode | undefined = getNode(__filename);
  const hapContext = node?.getContext(OhosPluginId.OHOS_HAP_PLUGIN) as OhosHapContext;
  hapContext?.targets((target: Target) => {
    const targetName: string = target.getTargetName();
    node?.registerTask({
      name: `${targetName}@SyncI18n`,
      run: () => {
        const r = spawnSync(
          process.execPath,
          [join(dirname(__filename), '..', 'scripts', 'sync-i18n.mjs')],
          { stdio: 'inherit' },
        );
        if (r.status !== 0) {
          console.warn(`SyncI18n: 官方文案同步失败 (exit ${r.status})，使用现有 i18n 资源继续构建`);
        }
      },
      // PreBuild 之后、CompileResource 之前执行，保证打包资源为最新
      dependencies: [`${targetName}@PreBuild`],
      postDependencies: [`${targetName}@CompileResource`],
    });
  });
});

export default {
  system: hapTasks,  /* Built-in plugin of Hvigor. It cannot be modified. */
  plugins: []        /* Custom plugin to extend the functionality of Hvigor. */
}
