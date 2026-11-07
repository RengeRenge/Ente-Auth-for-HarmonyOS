import { common } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { WatchItem, WearRowRaw } from '../model/WatchItem';
import { Totp } from '../service/WatchTotp';
import { Store, Sealer } from '../service/WatchCache';
import { WatchSyncLike, loadWatchSync } from '../service/WatchSyncLoader';
import { toItem, toRaw, sortItems } from '../service/WatchItemUtil';

const TAG: string = 'WatchPage';
const PREF_NAME: string = 'watch_auth_cache';
const KEY_ROWS: string = 'rows_sealed';
const KEY_TS: string = 'sync_ts';
// 模拟器/预览演示数据开关：真机联调与上架前置为 false
const DEMO_SEED: boolean = false;

// 本地缓存结构
interface WatchCacheBlob {
  ts: number;
  rows: WearRowRaw[];
}

function pad2(v: number): string {
  return v < 10 ? '0' + v.toString() : v.toString();
}

// 倒计时圆环：帧级定时器（50ms）连续刷新进度值，圆环匀速减少无跳变
// 注：官方 FAQ 明确 animateTo 无法驱动 Progress 进度值，需用定时器方案
@Component
struct RingCountdown {
  @Prop period: number = 30;
  @State pct: number = 100;
  @State hot: boolean = true;
  private timer: number = -1;

  aboutToAppear(): void {
    this.refresh();
    this.timer = setInterval((): void => {
      this.refresh();
    }, 50);
  }

  aboutToDisappear(): void {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
  }

  private refresh(): void {
    if (this.period <= 0) {
      this.pct = 100;
      this.hot = true;
      return;
    }
    const periodMs: number = this.period * 1000;
    const rem: number = periodMs - (Date.now() % periodMs);
    const next: number = rem / periodMs * 100;
    this.pct = next;
    this.hot = next > 40;
  }

  build() {
    Progress({ value: this.pct, total: 100, type: ProgressType.Ring })
      .style({ strokeWidth: 2.5, enableSmoothEffect: false })
      .width(16)
      .height(16)
      .color(this.hot ? '#69F0AE' : '#FFB74D')
      .backgroundColor('#2C2C2E')
  }
}

@Entry
@Component
struct WatchPage {
  @State items: WatchItem[] = [];
  @State syncTime: number = 0;
  @State syncing: boolean = false;
  private sync: WatchSyncLike | null = null;
  private store: Store | null = null;
  private timer: number = -1;

  aboutToAppear(): void {
    const ctx: common.Context = getContext(this) as common.Context;
    this.store = new Store(ctx, PREF_NAME);
    // 缓存优先展示，避免每次启动都等待同步
    this.loadCache();
    // 无缓存且开启演示开关时注入示例数据（走真实加密缓存路径，便于模拟器查看界面）
    this.seedDemo();
    // WearEngine 按需动态加载，设备不支持时仅展示缓存
    this.initSync(ctx);
    this.timer = setInterval(() => {
      this.tick();
    }, 1000);
  }

  private async initSync(ctx: common.Context): Promise<void> {
    this.sync = await loadWatchSync(ctx, (items: WatchItem[], ts: number): void => {
      this.onSyncData(items, ts);
    });
    if (this.sync !== null) {
      await this.sync.start();
      this.requestSync();
    }
  }

  aboutToDisappear(): void {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
  }

  private tick(): void {
    this.ensureCodes();
  }

  // 演示数据：覆盖置顶/普通/steam/8 位/长名称等 UI 形态
  private seedDemo(): void {
    if (!DEMO_SEED || this.store === null) {
      return;
    }
    if (this.store.get(KEY_ROWS).length > 0) {
      return;
    }
    const raws: WearRowRaw[] = [
      { i: 'demo1', s: 'GitHub', a: 'dev@ente.io', k: 'JBSWY3DPEHPK3PXP', d: 6, p: 30, g: 'sha1', t: 'totp', pin: 1 },
      { i: 'demo2', s: 'Google', a: 'user@gmail.com', k: 'JBSWY3DPEHPK3PXQ', d: 6, p: 30, g: 'sha1', t: 'totp', pin: 0 },
      { i: 'demo3', s: 'Steam', a: 'steam_user', k: 'JBSWY3DPEHPK3PXR', d: 5, p: 30, g: 'sha1', t: 'steam', pin: 0 },
      { i: 'demo4', s: 'Amazon Web Services', a: 'ops@company.example.com', k: 'JBSWY3DPEHPK3PXS', d: 8, p: 30, g: 'sha1', t: 'totp', pin: 0 },
      { i: 'demo5', s: 'Microsoft', a: 'work@outlook.com', k: 'JBSWY3DPEHPK3PXT', d: 6, p: 60, g: 'sha1', t: 'totp', pin: 0 },
      { i: 'demo6', s: 'Cloudflare', a: 'admin@example.net', k: 'JBSWY3DPEHPK3PXU', d: 6, p: 30, g: 'sha1', t: 'totp', pin: 0 },
    ];
    const items: WatchItem[] = [];
    for (const r of raws) {
      items.push(toItem(r));
    }
    sortItems(items);
    this.items = items;
    this.syncTime = Date.now();
    this.saveCache();
    this.ensureCodes();
  }

  private onSyncData(items: WatchItem[], ts: number): void {
    this.items = items;
    this.syncTime = ts;
    this.saveCache();
    this.ensureCodes();
  }

  // 为新时间步生成验证码；无变化不触发列表重建
  private async ensureCodes(): Promise<void> {
    let changed: boolean = false;
    for (const it of this.items) {
      if (it.secret.length === 0) {
        continue;
      }
      const step: number = Math.floor(Date.now() / 1000 / it.period);
      if (it.step === step) {
        continue;
      }
      it.step = step;
      it.code = await Totp.generate(it.secret, it.algorithm, it.digits, it.period, it.type, 0);
      changed = true;
    }
    if (changed) {
      this.items = this.items.slice();
    }
  }

  private async loadCache(): Promise<void> {
    if (this.store === null) {
      return;
    }
    const blob: string = this.store.get(KEY_ROWS);
    if (blob.length === 0) {
      return;
    }
    const json: string = await Sealer.unseal(blob);
    if (json.length === 0) {
      return;
    }
    try {
      const cache: WatchCacheBlob = JSON.parse(json) as WatchCacheBlob;
      const tsBuf: string = this.store.get(KEY_TS);
      const ts: number = tsBuf.length > 0 ? parseInt(tsBuf, 10) : 0;
      const items: WatchItem[] = [];
      for (const r of cache.rows) {
items.push(toItem(r));
      }
      sortItems(items);
      if (items.length > 0) {
        this.items = items;
        this.syncTime = ts;
        this.ensureCodes();
      }
    } catch (e) {
      hilog.info(0x0000, TAG, 'cache broken: %{public}s', JSON.stringify(e));
    }
  }

  private async saveCache(): Promise<void> {
    if (this.store === null) {
      return;
    }
    try {
      const raws: WearRowRaw[] = [];
      for (const it of this.items) {
        raws.push(toRaw(it));
      }
      const cache: WatchCacheBlob = { ts: this.syncTime, rows: raws };
      const sealed: string = await Sealer.seal(JSON.stringify(cache));
      this.store.put(KEY_ROWS, sealed);
      this.store.put(KEY_TS, this.syncTime.toString());
    } catch (e) {
      // 缓存失败不影响展示
    }
  }

  private requestSync(): void {
    if (this.sync === null || this.syncing) {
      return;
    }
    this.syncing = true;
    this.sync.requestSync().then((sent: boolean): void => {
      this.syncing = false;
      if (!sent) {
        hilog.info(0x0000, TAG, 'no connected phone');
      }
    }).catch((): void => {
      this.syncing = false;
    });
  }

  private syncLabel(): string {
    if (this.syncTime > 0) {
      const d: Date = new Date(this.syncTime);
      return '已同步 ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
    }
    return this.syncing ? '同步中' : '点击同步';
  }

  private itemTitle(it: WatchItem): string {
    return it.issuer.length > 0 ? it.issuer : it.account;
  }

  private formatCode(it: WatchItem): string {
    if (it.code.length === 0) {
      return '------';
    }
    if (it.type === 'steam') {
      return it.code;
    }
    const parts: string[] = [];
    for (let i = 0; i < it.code.length; i += 3) {
      const end: number = Math.min(i + 3, it.code.length);
      parts.push(it.code.substring(i, end));
    }
    return parts.join(' ');
  }

  @Builder
  private itemCard(it: WatchItem) {
    Row({ space: 8 }) {
      Column({ space: 2 }) {
        Text(this.itemTitle(it))
          .fontSize(10)
          .fontColor(it.pinned ? '#FFD54F' : '#9AA0A6')
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(this.formatCode(it))
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .fontColor(Color.White)
          .maxLines(1)
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      RingCountdown({ period: it.period })
    }
    .width('100%')
    .padding({ left: 12, right: 12, top: 9, bottom: 9 })
    .borderRadius(14)
    .backgroundColor('#1C1C1E')
  }

  build() {
    if (this.items.length === 0) {
      Column({ space: 6 }) {
        Text('Ente Auth')
          .fontSize(13)
          .fontWeight(FontWeight.Bold)
          .fontColor(Color.White)
        Text(this.syncLabel())
          .fontSize(9)
          .fontColor(this.syncTime > 0 ? '#8BC34A' : '#9AA0A6')
          .onClick(() => {
            this.requestSync();
          })
        Text(this.syncTime > 0 ? '暂无验证码' : (this.syncing ? '正在同步' : '等待同步'))
          .fontSize(13)
          .fontColor('#E8E8E8')
          .margin({ top: 10 })
        Text('打开手机端 Ente Auth 完成同步')
          .fontSize(9)
          .fontColor('#9AA0A6')
      }
      .width('100%')
      .height('100%')
      .padding({ left: 20, right: 20 })
      .justifyContent(FlexAlign.Center)
      .backgroundColor('#000000')
    } else {
      // 标题在顶、同步时间在底，整体随列表滚动，不固定
      List({ space: 6 }) {
        ListItem() {
          Text('Ente Auth')
            .fontSize(13)
            .fontWeight(FontWeight.Bold)
            .fontColor(Color.White)
            .width('100%')
            .textAlign(TextAlign.Center)
            // 顶部滑动空间：列表停在最顶时标题距屏 ~24px；滚动时随内容滑走，不产生固定黑边
            .padding({ top: 10 })
        }
        ForEach(this.items, (it: WatchItem) => {
          ListItem() {
            this.itemCard(it)
          }
        }, (it: WatchItem) => it.id + '_' + it.step)
        ListItem() {
          Text(this.syncLabel())
            .fontSize(9)
            .fontColor(this.syncTime > 0 ? '#8BC34A' : '#9AA0A6')
            .width('100%')
            .textAlign(TextAlign.Center)
            // 底部滑动空间：列表滚到最底时同步时间距屏 ~24px；滚动时随内容滑走
            .padding({ top: 2, bottom: 10 })
            .onClick(() => {
              this.requestSync();
            })
        }
      }
      .layoutWeight(1)
      .width('100%')
      // 左右保留 20vp（=40px）圆弧安全区；上下不内缩（圆屏正上/正下中线全高可见）
      // 注意本机密度 2.0：vp 数值 × 2 才是实际像素
      .padding({ left: 20, right: 20 })
      .backgroundColor('#000000')
      .edgeEffect(EdgeEffect.Spring)
      .scrollBar(BarState.Off)
    }
  }
}
