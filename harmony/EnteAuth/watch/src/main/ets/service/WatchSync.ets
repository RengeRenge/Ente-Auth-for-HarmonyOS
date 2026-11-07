import { wearEngine } from '@kit.WearEngine';
import { common } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { WatchItem, WearRowRaw } from '../model/WatchItem';
import { WatchSyncLike } from './WatchSyncLoader';
import { toItem, sortItems } from './WatchItemUtil';

const TAG: string = 'WatchSync';

// 手机端与本端为同一应用（bundleName 相同）；指纹需按签名证书填写：
// 调试期：hdc shell bm dump -n com.enteauth.renge | findstr appIdentifier
// 正式上架：AGC「证书、APP ID 和 Profile」页获取
export const PHONE_APP_BUNDLE: string = 'com.enteauth.renge';
export const PHONE_APP_FINGERPRINT: string = 'TODO_FILL_APP_FINGERPRINT';

// 手机 -> 手表：同步分片
interface WearChunk {
  t: string;
  rev: number;
  seq: number;
  total: number;
  ts: number;
  rows: WearRowRaw[];
}

// 手表 -> 手机：请求同步
interface WearReq {
  t: string;
  v: number;
}

// Wear Engine P2P 客户端封装：接收手机分片并重组、发起同步请求
// 仅经 WatchSyncLoader 动态导入加载，不得被页面静态引用
export class WatchSync implements WatchSyncLike {
  private deviceClient: wearEngine.DeviceClient;
  private p2pClient: wearEngine.P2pClient;
  private onData: (items: WatchItem[], syncTime: number) => void;
  private msgCallback: (msg: wearEngine.P2pMessage) => void;
  private registeredIds: Set<string> = new Set<string>();
  // 分片重组状态
  private rev: number = 0;
  private parts: Array<WearRowRaw[] | null> = [];
  private gotCount: number = 0;

  constructor(ctx: common.Context, onData: (items: WatchItem[], syncTime: number) => void) {
    this.onData = onData;
    this.deviceClient = wearEngine.getDeviceClient(ctx);
    this.p2pClient = wearEngine.getP2pClient(ctx);
    this.msgCallback = (msg: wearEngine.P2pMessage): void => {
      this.handleMessage(msg);
    };
  }

  // 启动即注册消息接收；手机侧推送到达时自动回调 onData
  async start(): Promise<void> {
    await this.ensureReceivers();
  }

  // 向手机请求一次全量同步；返回是否至少向一台设备发出请求
  async requestSync(): Promise<boolean> {
    try {
      await this.ensureReceivers();
      const devices: wearEngine.Device[] = await this.deviceClient.getConnectedDevices();
      if (devices.length === 0) {
        return false;
      }
      const req: WearReq = { t: 'req', v: 1 };
      const msg: wearEngine.P2pMessage = {
        content: new util.TextEncoder().encodeInto(JSON.stringify(req)),
      };
      let sent: boolean = false;
      for (const d of devices) {
        try {
          await this.p2pClient.sendMessage(d.randomId, this.appParam(), msg);
          sent = true;
        } catch (e) {
          hilog.info(0x0000, TAG, 'send req failed: %{public}s', JSON.stringify(e));
        }
      }
      return sent;
    } catch (e) {
      hilog.info(0x0000, TAG, 'requestSync failed: %{public}s', JSON.stringify(e));
      return false;
    }
  }

  private appParam(): wearEngine.P2pAppParam {
    const appInfo: wearEngine.AppInfo = {
      bundleName: PHONE_APP_BUNDLE,
      fingerprint: PHONE_APP_FINGERPRINT,
    };
    return { remoteApp: appInfo };
  }

  private handleMessage(msg: wearEngine.P2pMessage): void {
    const text: string = new util.TextDecoder().decodeToString(msg.content);
    let chunk: WearChunk;
    try {
      chunk = JSON.parse(text) as WearChunk;
    } catch (e) {
      return;
    }
    if (chunk.t !== 'sync' || chunk.total <= 0 || chunk.seq < 0 || chunk.seq >= chunk.total) {
      return;
    }
    if (chunk.rev !== this.rev) {
      this.rev = chunk.rev;
      this.gotCount = 0;
      this.parts = [];
      for (let i = 0; i < chunk.total; i++) {
        this.parts.push(null);
      }
    }
    if (this.parts[chunk.seq] === null) {
      this.gotCount++;
    }
    this.parts[chunk.seq] = chunk.rows;
    if (this.gotCount < chunk.total) {
      return;
    }
    const raws: WearRowRaw[] = [];
    for (let i = 0; i < chunk.total; i++) {
      const p: WearRowRaw[] | null = this.parts[i];
      if (p === null) {
        return;
      }
      for (const r of p) {
        raws.push(r);
      }
    }
    const items: WatchItem[] = [];
    for (const r of raws) {
      items.push(toItem(r));
    }
    sortItems(items);
    this.rev = 0;
    this.parts = [];
    this.gotCount = 0;
    this.onData(items, chunk.ts);
  }

  private async ensureReceivers(): Promise<void> {
    try {
      const devices: wearEngine.Device[] = await this.deviceClient.getConnectedDevices();
      for (const d of devices) {
        if (this.registeredIds.has(d.randomId)) {
          continue;
        }
        try {
          await this.p2pClient.registerMessageReceiver(d.randomId, this.appParam(), this.msgCallback);
          this.registeredIds.add(d.randomId);
        } catch (e) {
          hilog.info(0x0000, TAG, 'register failed: %{public}s', JSON.stringify(e));
        }
      }
    } catch (e) {
      hilog.info(0x0000, TAG, 'list devices failed: %{public}s', JSON.stringify(e));
    }
  }
}
