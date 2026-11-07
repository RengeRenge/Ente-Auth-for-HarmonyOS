import { common } from '@kit.AbilityKit';
import { deviceInfo } from '@kit.BasicServicesKit';
import { WatchItem } from '../model/WatchItem';

// 手表侧同步对外接口：与 WatchSync 实现解耦，避免页面静态依赖 WearEngine 共享 HSP
export interface WatchSyncLike {
  start(): Promise<void>;
  requestSync(): Promise<boolean>;
}

// 按需动态加载：仅穿戴设备形态且系统具备 WearEngine 能力时才导入实现；否则返回 null 仅展示缓存
export async function loadWatchSync(ctx: common.Context,
  onData: (items: WatchItem[], ts: number) => void): Promise<WatchSyncLike | null> {
  if (deviceInfo.deviceType !== 'wearable') {
    return null;
  }
  if (!canIUse('SystemCapability.Health.WearEngine')) {
    return null;
  }
  try {
    const mod = await import('./WatchSync');
    return new mod.WatchSync(ctx, onData);
  } catch (e) {
    return null;
  }
}
