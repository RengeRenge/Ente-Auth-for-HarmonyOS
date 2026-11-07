import { wearEngine } from '@kit.WearEngine';
import { common } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { OtpRow } from '../model/OtpRow';
import { WearSyncLike } from './WearSyncLoader';

const TAG: string = 'WearSync';
// P2P 单条消息上限 4096 字节，按 3000 打包留余量
const MAX_CHUNK_BYTES: number = 3000;

// 手表端与本端为同一应用（bundleName 相同）；指纹需按签名证书填写：
// 调试期：hdc shell bm dump -n com.enteauth.renge | findstr appIdentifier
// 正式上架：AGC「证书、APP ID 和 Profile」页获取
export const WEAR_APP_BUNDLE: string = 'com.enteauth.renge';
export const WEAR_APP_FINGERPRINT: string = 'TODO_FILL_APP_FINGERPRINT';

// 同步行（紧凑字段名，节省 P2P 消息字节）
interface WearRowRaw {
  i: string;
  s: string;
  a: string;
  k: string;
  d: number;
  p: number;
  g: string;
  t: string;
  pin: number;
}

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

// Wear Engine P2P 推送封装：行数据变化时向手表分片推送；手表请求时即时响应
// 仅经 WearSyncLoader 动态导入加载，不得被启动页静态引用
export class WearSync implements WearSyncLike {
  private deviceClient: wearEngine.DeviceClient;
  private p2pClient: wearEngine.P2pClient;
  private provider: () => OtpRow[] | null;
  private msgCallback: (msg: wearEngine.P2pMessage) => void;
  private registeredIds: Set<string> = new Set<string>();
  private started: boolean = false;
  private pushing: boolean = false;
  private dirty: boolean = false;

  constructor(ctx: common.Context, provider: () => OtpRow[] | null) {
    this.provider = provider;
    this.deviceClient = wearEngine.getDeviceClient(ctx);
    this.p2pClient = wearEngine.getP2pClient(ctx);
    this.msgCallback = (msg: wearEngine.P2pMessage): void => {
      this.handleMessage(msg);
    };
  }

  async start(): Promise<void> {
    this.started = true;
    await this.ensureReceivers();
  }

  async stop(): Promise<void> {
    this.started = false;
    try {
      const devices: wearEngine.Device[] = await this.deviceClient.getConnectedDevices();
      for (const d of devices) {
        if (this.registeredIds.has(d.randomId)) {
          try {
            await this.p2pClient.unregisterMessageReceiver(d.randomId, this.appParam(), this.msgCallback);
          } catch (e) {
            // 取消订阅失败时忽略
          }
          this.registeredIds.delete(d.randomId);
        }
      }
    } catch (e) {
      // 设备不可用时忽略
    }
  }

  // 行数据变化后推送到手表；provider 返回 null（应用锁定）时跳过
  async push(): Promise<void> {
    if (!this.started) {
      return;
    }
    if (this.pushing) {
      this.dirty = true;
      return;
    }
    this.pushing = true;
    this.dirty = false;
    try {
      await this.ensureReceivers();
      const devices: wearEngine.Device[] = await this.deviceClient.getConnectedDevices();
      if (devices.length > 0) {
        const rows: OtpRow[] | null = this.provider();
        if (rows !== null) {
          const chunks: WearChunk[] = WearSync.buildChunks(rows);
          for (const d of devices) {
            await this.sendChunks(d, chunks);
          }
        }
      }
    } catch (e) {
      hilog.info(0x0000, TAG, 'push skipped: %{public}s', JSON.stringify(e));
    } finally {
      this.pushing = false;
      if (this.dirty) {
        this.dirty = false;
        this.push();
      }
    }
  }

  private async sendChunks(d: wearEngine.Device, chunks: WearChunk[]): Promise<void> {
    for (const c of chunks) {
      try {
        const msg: wearEngine.P2pMessage = {
          content: new util.TextEncoder().encodeInto(JSON.stringify(c)),
        };
        await this.p2pClient.sendMessage(d.randomId, this.appParam(), msg);
      } catch (e) {
        hilog.info(0x0000, TAG, 'send to %{public}s failed', d.randomId);
        return;
      }
    }
  }

  private appParam(): wearEngine.P2pAppParam {
    const appInfo: wearEngine.AppInfo = {
      bundleName: WEAR_APP_BUNDLE,
      fingerprint: WEAR_APP_FINGERPRINT,
    };
    return { remoteApp: appInfo };
  }

  private handleMessage(msg: wearEngine.P2pMessage): void {
    try {
      const text: string = new util.TextDecoder().decodeToString(msg.content);
      const req: WearReq = JSON.parse(text) as WearReq;
      if (req.t === 'req') {
        this.push();
      }
    } catch (e) {
      // 非法消息忽略
    }
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

  private static toRaw(r: OtpRow): WearRowRaw {
    const raw: WearRowRaw = {
      i: r.id,
      s: r.issuer,
      a: r.account,
      k: r.secret,
      d: r.digits,
      p: r.period,
      g: r.algorithm,
      t: r.type,
      pin: r.pinned ? 1 : 0,
    };
    return raw;
  }

  // 过滤并分片：跳过已删除/损坏/HOTP（手表端无法安全推进计数器）
  private static buildChunks(rows: OtpRow[]): WearChunk[] {
    const raws: WearRowRaw[] = [];
    for (const r of rows) {
      if (r.trashed || r.broken || r.secret.length === 0) {
        continue;
      }
      if (r.type === 'hotp') {
        continue;
      }
      raws.push(WearSync.toRaw(r));
    }
    const groups: WearRowRaw[][] = WearSync.splitRows(raws);
    const ts: number = Date.now();
    const chunks: WearChunk[] = [];
    for (let i = 0; i < groups.length; i++) {
      const c: WearChunk = {
        t: 'sync',
        rev: ts,
        seq: i,
        total: groups.length,
        ts: ts,
        rows: groups[i],
      };
      chunks.push(c);
    }
    return chunks;
  }

  // 按字节预算分组，保证单条消息不超过 P2P 上限
  private static splitRows(raws: WearRowRaw[]): WearRowRaw[][] {
    const encoder = new util.TextEncoder();
    const groups: WearRowRaw[][] = [];
    let cur: WearRowRaw[] = [];
    let curBytes: number = 96;
    for (const r of raws) {
      const size: number = encoder.encodeInto(JSON.stringify(r)).byteLength + 1;
      if (curBytes + size > MAX_CHUNK_BYTES && cur.length > 0) {
        groups.push(cur);
        cur = [];
        curBytes = 96;
      }
      cur.push(r);
      curBytes += size;
    }
    if (cur.length > 0) {
      groups.push(cur);
    }
    if (groups.length === 0) {
      // 空列表也下发一条，让手表清空
      groups.push([]);
    }
    return groups;
  }
}
