import { common } from '@kit.AbilityKit';
import { deviceInfo } from '@kit.BasicServicesKit';
import { OtpRow } from '../model/OtpRow';

// 手表同步对外接口：与 WearSync 实现解耦。
// @kit.WearEngine 依赖华为运动健康的共享 HSP（com.huawei.hmos.health.kit/WearEngine），
// PC/2in1 等设备上不存在；若静态编入启动页模块图，模块实例化时会直接 abort 启动崩溃。
export interface WearSyncLike {
  start(): Promise<void>;
  stop(): Promise<void>;
  push(): Promise<void>;
}

// 按需动态加载：仅手机/平板形态且系统具备 WearEngine 能力时才导入实现；
// 其余设备返回 null 优雅降级（无手表同步，不触发共享 HSP 加载）。
export async function loadWearSync(ctx: common.Context, provider: () => OtpRow[] | null): Promise<WearSyncLike | null> {
  if (deviceInfo.deviceType !== 'phone' && deviceInfo.deviceType !== 'tablet') {
    return null;
  }
  if (!canIUse('SystemCapability.Health.WearEngine')) {
    return null;
  }
  try {
    const mod = await import('./WearSync');
    return new mod.WearSync(ctx, provider);
  } catch (e) {
    return null;
  }
}
