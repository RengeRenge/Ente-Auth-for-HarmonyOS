import { webview } from '@kit.ArkWeb';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window, uiMaterial, display, font, KeyboardAvoidMode } from '@kit.ArkUI';
import { util } from '@kit.ArkTS';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { pasteboard } from '@kit.BasicServicesKit';
import { systemShare } from '@kit.ShareKit';
import { promptAction } from '@kit.ArkUI';
import { common, EnvironmentCallback, Configuration, ConfigurationConstant, AbilityConstant, abilityAccessCtrl, bundleManager, PermissionRequestResult, Permissions } from '@kit.AbilityKit';
import { picker, fileIo } from '@kit.CoreFileKit';
import { resourceManager, i18n } from '@kit.LocalizationKit';
import { motion } from '@kit.MultimodalAwarenessKit';
import { scanBarcode, scanCore } from '@kit.ScanKit';
import { Bridge, PollPayload, BridgeResult, rowsFromPayload } from '../service/Bridge';
import { OtpRow } from '../model/OtpRow';
import { Totp, base32Decode } from '../service/Totp';
import { Sealer } from '../service/Huks';
import { Store } from '../service/Store';
import { Biometrics } from '../service/Biometrics';
import { WearSyncLike, loadWearSync } from '../service/WearSyncLoader';
import { deriveKek, argon2SelfTest } from '../service/Argon2';

const TAG: string = 'EnteAuth';
const START_URL: string = 'https://auth.ente.com';
// 官方 web 登录路由：登出后直接进入，避免先加载根路径再重定向
const LOGIN_URL: string = 'https://auth.ente.com/login';
const PREF_NAME: string = 'ente_auth_prefs';
const KEY_SESSION: string = 'session_enc';
const KEY_CACHE: string = 'cache_rows';
const KEY_LEFTMODE: string = 'left_mode';
const KEY_APPLOCK: string = 'app_lock';

// 主题模式：0 跟随系统 / 1 浅色 / 2 深色（浅色对齐官方 Ente Auth Flutter 主题）
const THEME_SYSTEM: number = 0;
const THEME_LIGHT: number = 1;
const THEME_DARK: number = 2;
const KEY_THEME: string = 'theme_mode';
const KEY_BIG_ICONS: string = 'big_icons';
const KEY_COMPACT: string = 'compact_mode';
const KEY_COPY_MIN: string = 'copy_minimize';
const KEY_HIDE_CODES: string = 'hide_codes';
const KEY_BACKUP_ON: string = 'backup_enabled';
const KEY_BACKUP_PWD: string = 'backup_password';
const KEY_LOCK_DELAY: string = 'lock_delay';
const KEY_LOCALE: string = 'locale';
const KEY_SORT: string = 'sort_mode';
const KEY_TAG_FILTER: string = 'tag_filter';
const KEY_USAGE: string = 'usage_stats';
const KEY_CUSTOM_ORDER: string = 'custom_order';

// 首次启动必须明示同意隐私政策与用户协议
const KEY_PRIVACY: string = 'privacy_accepted';
const PRIVACY_URL: string = 'https://renged.xyz/static/page/ente/privacy.html';
const TERMS_URL: string = 'https://renged.xyz/static/page/ente/terms.html';
const REPO_URL: string = 'https://github.com/RengeRenge/Ente-Auth-for-HarmonyOS.git';

// 首页排序方式（对齐官方「编辑顺序」）
const SORT_ISSUER: number = 0;
const SORT_ACCOUNT: number = 1;
const SORT_FREQUENT: number = 2;
const SORT_RECENT: number = 3;
const SORT_CUSTOM: number = 4;

// 官方 app 支持的全部语言（顺序与 locale.dart 一致）
const LOCALE_CODES: string[] = [
  'ar', 'bg', 'ca', 'cs', 'de', 'el', 'en', 'es', 'fa', 'fr', 'he', 'hu',
  'id', 'it', 'ja', 'ko', 'lt', 'nl', 'pl', 'pt_BR', 'ro', 'ru', 'sl', 'sk',
  'tr', 'uk', 'vi', 'zh_CN', 'zh_TW',
];

// 官方头像回退配色（avatarLight）
const AVATAR_COLORS: string[] = [
  '#76549A', '#DF7861', '#94B49F', '#87A2FB', '#C689C6', '#C689C6',
  '#325288', '#85B4E0', '#C1A3A3', '#C1A3A3', '#426165', '#426165',
  '#426165', '#DD9DE2', '#82AB8B', '#9BBBE8', '#8FBEBE', '#8AC3A1',
  '#A8B0F2', '#B0C695', '#E99AAD', '#D18484', '#78B5A7',
];

// 本工程新增的注入脚本（resources/rawfile/ext 下），不改动 ente 仓库任何源码
const EXT_SCRIPTS: string[] = [
  'ext/libsodium-sumo.js',
  'ext/libsodium-wrappers-sumo.js',
  'ext/bip39-en.js',
  'ext/ente-ext.js',
];

interface SessionInfo {
  token: string;
  isCurrent: boolean;
  creationTime: number;
  lastUsedTime: number;
  ip: string;
  prettyUA: string;
  ua: string;
}

interface SessionsPayload {
  sessions: SessionInfo[];
}

interface RecoveryPayload {
  mnemonic: string;
  hex: string;
}

interface EmailMfaPayload {
  enabled: boolean;
  canDisable: boolean;
}

interface PasskeyUrlPayload {
  url: string;
}

interface UserReadyPayload {
  ready: boolean;
}

// 原生 SRP 登录：loginPrepare 返回（账户是否启用邮箱 MFA + 服务端 KDF 参数，
// 原生 taskpool Argon2id 派生 kek 用）
interface LoginPreparePayload {
  isEmailMFAEnabled: boolean;
  kekSalt?: string;
  opsLimit?: number;
  memLimit?: number;
}

// 原生 SRP 登录：loginPassword 返回（需要两步验证 / 需要通行密钥 / 已完成）
interface LoginAuthPayload {
  needs2FA?: boolean;
  needsPasskey?: boolean;
}

// 登录响应通用分流（verifyOtt / loginTotp / passkeyStatus）：
// next = passkey | twofactor | unlock | setpassword | done；unlock 附 KDF 参数
interface LoginNextPayload {
  next?: string;
  done?: boolean;
  verified?: boolean;
  kekSalt?: string;
  opsLimit?: number;
  memLimit?: number;
}

// 注册 KDF 参数阶梯（官方移动端：256MiB/16 主档，分配失败回退 128MiB/32）
interface KdfAttempt {
  ops: number;
  mem: number;
}

// signupPrepare 返回恢复密钥助记词
interface SignupPreparePayload {
  mnemonic: string;
}

// passkeyVerifyUrl 返回验证页地址 + 是否可改用 TOTP
interface PasskeyVerifyUrlPayload {
  url: string;
  totpAvailable: boolean;
}

// 服务条款富文本解析片段（kind：'' 普通文本 / terms 条款 / policy 政策）
interface TosSegment {
  text: string;
  kind: string;
}

interface ProviderIconEntry {
  title: string;
  slug?: string;
  hex?: string;
  altNames?: string[];
}

interface ProviderIconsFile {
  icons: ProviderIconEntry[];
}

interface ProviderIcon {
  slug: string;
  hex: string;
}

// 沉浸材质运行时包装：低版本系统（API<26 无 uiMaterial）不调用 systemMaterial，保留常规样式；
// 启动守卫确认支持后回填 style，未回填时 applyNormalAttribute 直接跳过
class SysMatButtonModifier implements AttributeModifier<ButtonAttribute> {
  private style: uiMaterial.ImmersiveStyle | undefined = undefined;
  private readonly light: string;

  constructor(light: string) {
    this.light = light;
  }

  setStyle(style: uiMaterial.ImmersiveStyle): void {
    this.style = style;
  }

  applyNormalAttribute(instance: ButtonAttribute): void {
    const style: uiMaterial.ImmersiveStyle | undefined = this.style;
    if (style === undefined) {
      return;
    }
    instance.systemMaterial(new uiMaterial.ImmersiveMaterial({
      style: style,
      materialColor: '#14FFFFFF',
      colorInvert: false,
      applyShadow: true,
      interactive: true,
      lightEffect: { color: this.light },
    }));
  }
}

class SysMatColumnModifier implements AttributeModifier<ColumnAttribute> {
  private style: uiMaterial.ImmersiveStyle | undefined = undefined;
  private readonly light: string;

  constructor(light: string) {
    this.light = light;
  }

  setStyle(style: uiMaterial.ImmersiveStyle): void {
    this.style = style;
  }

  applyNormalAttribute(instance: ColumnAttribute): void {
    const style: uiMaterial.ImmersiveStyle | undefined = this.style;
    if (style === undefined) {
      return;
    }
    instance.systemMaterial(new uiMaterial.ImmersiveMaterial({
      style: style,
      materialColor: '#14FFFFFF',
      colorInvert: false,
      applyShadow: true,
      interactive: true,
      lightEffect: { color: this.light },
    }));
  }
}

// 卡片顶部计时条：独立组件，自管定时器，避免整页随进度高频重建而闪烁
@Component
struct CodeBar {
  @Prop period: number = 30;
  @Prop barHeight: number = 3;
  @Prop hotColor: string = '#FFB37FEB';
  @Prop coldColor: string = '#FFFF9F43';
  @Prop isHotp: boolean = false;
  @State pct: number = 100;
  @State hot: boolean = true;
  private timer: number = -1;
  private wasReset: boolean = true;

  aboutToAppear(): void {
    this.refresh();
    if (!this.isHotp) {
      this.timer = setInterval(() => {
        this.refresh();
      }, 120);
    }
  }

  aboutToDisappear(): void {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
  }

  private refresh(): void {
    if (this.period <= 0 || this.isHotp) {
      this.pct = 100;
      this.hot = true;
      return;
    }
    const periodMs: number = this.period * 1000;
    const rem: number = periodMs - (Date.now() % periodMs);
    const next: number = Math.max(0, Math.min(100, rem / periodMs * 100));
    // 周期刚开始时不做补间，避免出现“反向回涨”的动画
    this.wasReset = next > this.pct + 20;
    this.pct = next;
    this.hot = rem / periodMs > 0.4;
  }

  build() {
    Row()
      .width(this.pct.toFixed(2) + '%')
      .height(this.barHeight)
      .backgroundColor(this.hot ? this.hotColor : this.coldColor)
      .borderRadius(this.barHeight / 2)
      .animation({ duration: this.wasReset ? 0 : 140, curve: Curve.Linear })
  }
}

// 系统环境（深浅色）变化回调：EnvironmentCallback 是类，需要继承实现
class PageEnvCallback extends EnvironmentCallback {
  private handler: (config: Configuration) => void;

  constructor(handler: (config: Configuration) => void) {
    super();
    this.handler = handler;
  }

  onConfigurationUpdated(config: Configuration): void {
    this.handler(config);
  }

  onMemoryLevel(level: AbilityConstant.MemoryLevel): void {
  }
}

@Entry
@Component
struct Index {
  private controller: webview.WebviewController = new webview.WebviewController();
  private bridge: Bridge | null = null;
  private store: Store | null = null;
  private wearSync: WearSyncLike | null = null;
  private ctx: common.Context | null = null;
  private providerIcons: Map<string, ProviderIcon> = new Map<string, ProviderIcon>();

  private timer: number = -1;
  private polling: boolean = false;
  // 退出登录清理进行中：pollBridge 只分发桥结果，不处理登录态探测，
  // 避免清理尚未生效时又被误判成“登录成功”而拉回首页
  private loggingOut: boolean = false;
  private listBusy: boolean = false;
  private codeBusy: boolean = false;
  // 当前需要加载的入口地址：启动用 START_URL，登出后切到 LOGIN_URL
  private startUrl: string = START_URL;
  // 应用内打开外部账户页的目标地址（完整 URL）与其去 query 前缀：
  // Web 从 None 切回 Visible 时底层可能重建并重载 src，打断目标导航，用其自愈
  private webTargetUrl: string = '';
  private webTargetBase: string = '';
  private sessionSaved: boolean = false;
  private sessionSaving: boolean = false;
  private retried401: boolean = false;
  private totpChecked: boolean = false;
  private srpSelfChecked: boolean = false;
  private nextListAt: number = 0;
  private nextReloadAt: number = 0;
  private loadFailed: boolean = false;
  private backupPwdCache: string = '';
  private backupDone: boolean = false;
  private lastListPayload: string = '';
  private pageName: string = '';

  @State webReady: boolean = false;

  @State scripts: Array<ScriptItem> = [];
  @State scriptsReady: boolean = false;
  @State mode: string = 'boot'; // boot | web | ready
  @State bioOk: boolean = true;
  @State rows: OtpRow[] = [];
  @State nowMs: number = Date.now();
  @State query: string = '';
  @State tagFilter: string = '';
  @State tagMenuOpen: boolean = false;
  @State tagMenuTag: string = '';
  @State tagEditOpen: boolean = false;
  @State tagEditText: string = '';
  @State tagDeleteOpen: boolean = false;
  @State notice: string = '';

  // 全屏布局下的状态栏高度（vp）
  @State topInset: number = 0;
  // 窗口尺寸（vp）：用于旋转适配（横屏时限制内容宽度、抽屉宽度）
  @State rootW: number = 0;
  @State rootH: number = 0;
  // 无键盘时的窗口高度（vp）：键盘 RESIZE 只压缩高度不改宽度，宽度变化（旋转/折叠）
  // 时重置、否则取历史最大值。布局断点用它，避免键盘弹出导致上下/左右布局翻转
  @State stableH: number = 0;
  @State landscape: boolean = false;
  // 左右/底部安全区（vp）：横屏挖孔、导航条等，供悬浮按钮避让
  @State safeL: number = 0;
  @State safeR: number = 0;
  @State safeB: number = 0;

  // 侧边抽屉
  @State drawerOpen: boolean = false;
  @State logoutConfirm: boolean = false;

  // 官方 App 交互：内联搜索、悬浮按钮展开
  @State searchOpen: boolean = false;
  @State fabOpen: boolean = false;

  // 鸿蒙原生能力：左右手握持自适应（自动感知 + 手动切换）
  @State leftMode: boolean = false;
  @State handAuto: boolean = false;
  // 换手动画的横向位移（vp）：先移到屏幕外，换边后从另一侧移入
  @State fabShift: number = 0;
  private handSwitching: boolean = false;
  @State immersiveOk: boolean = false;
  private matBtnUltraThin: SysMatButtonModifier = new SysMatButtonModifier('#FF984DF4');
  private matBtnThin: SysMatButtonModifier = new SysMatButtonModifier('#FFB37FEB');
  private matBtnFabChild: SysMatButtonModifier = new SysMatButtonModifier('#FFB37FEB');
  private matColRegular: SysMatColumnModifier = new SysMatColumnModifier('#FF984DF4');

  // 应用锁（启动/进入前台时生物识别）
  @State appLock: boolean = true;

  // 首启隐私同意：privacyReady 为偏好读取完成，未同意前不创建 WebView
  @State privacyReady: boolean = false;
  @State privacyAccepted: boolean = false;

  // 主题与通用偏好
  @State themeMode: number = THEME_SYSTEM;
  @State dark: boolean = false;
  @State bigIcons: boolean = false;
  @State compact: boolean = false;
  @State copyMinimize: boolean = false;
  @State hideCodes: boolean = false;
  @State revealedId: string = '';
  @State lockDelay: number = 0;

  // 多语言：localeRev 作为 @State 依赖，切换语言后调用 tr() 的组件会自动重建
  @State locale: string = 'zh_CN';
  @State localeRev: number = 0;
  @State languageOpen: boolean = false;
  @State fabMenuW: number = 0;
  private i18nData: Map<string, Map<string, string>> = new Map<string, Map<string, string>>();

  // 导入导出 / 本地备份
  @State exportOpen: boolean = false;
  @State exportStep: number = 0; // 0 选择格式 / 1 输入加密密码 / 2 明文风险确认
  @State exportFormat: string = 'encrypted';
  @State exportPwd: string = '';
  @State exportBusy: boolean = false;
  @State importPwdOpen: boolean = false;
  @State importPwd: string = '';
  @State importFileName: string = '';
  @State importFileText: string = '';
  @State importBusy: boolean = false;
  // 导入说明弹层（对齐官方 instruction sheet）：plain/ente/2fas/aegis/andotp/openauth/bitwarden/ga/proton/raivo/lastpass/otpauth
  @State importGuideApp: string = '';
  @State importSuccessCount: number = -1; // >=0 时显示导入成功弹层
  @State backupOn: boolean = false;
  @State backupPwdSet: boolean = false;
  @State backupPath: string = '';
  @State backupBusy: boolean = false;
  @State backupPwdOpen: boolean = false;
  @State backupPwdInput: string = '';

  // 二级页面（导航入栈，自带返回按钮）
  @State qrUri: string = '';
  @State qrTitle: string = '';
  @State noteOpen: boolean = false;
  @State noteId: string = '';
  @State noteText: string = '';
  private pathStack: NavPathStack = new NavPathStack();

  private handCb: ((status: motion.HoldingHandStatus) => void) | null = null;
  private envCbId: number = -1;

  // 表单
  @State editId: string = '';
  @State formIssuer: string = '';
  @State formAccount: string = '';
  @State formSecret: string = '';
  @State formDigits: string = '6';
  @State formPeriod: string = '30';
  @State formAlg: number = 0; // 0 sha1 / 1 sha256 / 2 sha512
  @State formNote: string = '';
  @State formTags: string[] = [];
  @State secretVisible: boolean = false;
  @State advancedOpen: boolean = false;
  @State tagForForm: boolean = false;
  @State formType: string = 'totp';
  @State pickOpen: boolean = false;
  @State pickKind: number = 0; // 0 算法 / 1 类型

  // 长按菜单
  @State menuId: string = '';
  @State menuTitle: string = '';
  @State menuConfirm: boolean = false;

  // 多选（对齐官方：长按进入，底部操作项随选择结果变化）
  @State selectionMode: boolean = false;
  @State selectedIds: string[] = [];

  // 添加标签弹窗
  @State tagOpen: boolean = false;
  @State tagInput: string = '';
  @State selDeleteConfirm: boolean = false;

  // 排序（编辑顺序）
  @State sortOpen: boolean = false;
  @State sortMode: number = SORT_ISSUER;
  @State customOrder: string[] = [];
  @State usageRev: number = 0;
  private usageCount: Map<string, number> = new Map<string, number>();
  private usageLast: Map<string, number> = new Map<string, number>();

  // 导入导出
  // 重复代码页（对齐官方选择式清理）
  @State dupSelKeys: string[] = [];
  @State dupConfirmOpen: boolean = false;
  @State noDupOpen: boolean = false;

  // 账户 / 安全二级功能
  @State userEmail: string = '';
  @State appVersion: string = '';
  @State acctBusy: boolean = false;
  @State recoveryOpen: boolean = false;
  @State recoveryWords: string = '';
  @State emailOpen: boolean = false;
  @State emailStep: number = 0; // 0 输入新邮箱 / 1 输入验证码
  @State newEmail: string = '';
  @State emailOtt: string = '';
  @State sessionsOpen: boolean = false;
  @State sessionsLoading: boolean = false;
  @State sessions: SessionInfo[] = [];

  // 电子邮件验证（官方 email MFA 开关）
  @State emailMfaEnabled: boolean = false;
  @State emailMfaCanDisable: boolean = true;
  @State emailMfaLoading: boolean = false;
  @State emailMfaWarnOpen: boolean = false;

  // 应用内官方网页（修改密码 / 通行密钥），不跳转外部浏览器
  @State webPageOpen: boolean = false;
  @State webPageTitle: string = '';
  // 账户页请求校验 / 页面加载期间：隐藏 WebView，显示原生紫色加载圈
  @State webLoading: boolean = false;

  // 原生分步登录（隐藏 WebView 中的 SRP-4096 协议引擎）：0 邮箱 / 1 密码 / 2 两步验证码
  @State loginStep: number = 0;
  @State loginEmail: string = '';
  @State loginPwd: string = '';
  @State loginCode: string = '';
  @State @Watch('onLoginBusyChange') loginBusy: boolean = false;
  @State busySec: number = 0;
  private busyTimerId: number = -1;
  @State loginError: string = '';
  @State loginPwdVisible: boolean = false;
  @State loginFocus: string = '';
  @State otpFocusIdx: number = -1;
  // 步骤 1 模式：true = OTP 登录后输密码解锁（无 SRP 会话）
  @State loginPwdUnlock: boolean = false;
  // 当前登录流程 KDF 参数（loginPrepare / unlock 分流下发，原生 Argon2id 派生 kek 用）
  private loginKekSalt: string = '';
  private loginOpsLimit: number = 0;
  private loginMemLimit: number = 0;
  // 步骤 2 来源：true = 从 SRP 密码步骤进入（ext 侧已持有 kek）
  @State totpFromSrp: boolean = false;
  // 步骤 3 邮箱验证码用途：login | signup
  @State otpPurpose: string = '';
  // 步骤 4（登录路径设置密码）
  @State setPwd: string = '';
  @State setPwdConfirm: string = '';
  // 步骤 5 恢复密钥助记词
  @State signupMnemonic: string = '';
  // 步骤 6 通行密钥验证页
  @State passkeyUrl: string = '';
  @State passkeyTotpAvailable: boolean = false;
  @State passkeyChecking: boolean = false;
  @State passkeyWaitMs: number = 0;
  // 步骤 7 注册入口
  @State signupPwd: string = '';
  @State signupPwdConfirm: string = '';
  @State tosAccepted: boolean = true;
  // 步骤 8/9 恢复流程：忘记密码 → OTP → 恢复密钥（8）→ 重置新密码（9）
  @State resettingPassword: boolean = false;
  @State recoveryKeyInput: string = '';
  // 修改密码（原生页，账户页入口）：仅需新密码，会话已认证
  @State cpPwd: string = '';
  @State cpPwdConfirm: string = '';
  @State cpBusy: boolean = false;
  @State cpError: string = '';
  @State cpVisible: boolean = false;
  @State cpFocus1: boolean = false;
  @State cpFocus2: boolean = false;
  // 官方"退出其他设备"底部弹层：修改密码提交前选择
  @State cpLogOutSheetOpen: boolean = false;

  aboutToAppear(): void {
    // 键盘避让用压缩模式（默认 OFFSET 整体上抬不改变布局，短屏上表单滚动余量为 0、按钮被键盘永久遮挡）
    this.getUIContext().setKeyboardAvoidMode(KeyboardAvoidMode.RESIZE);
    // 原生 Argon2id 自测（异步，不阻塞启动）
    this.runArgon2SelfTest();
    // 官方 More from Ente 品牌区使用 Gochi Hand 手写字体
    try {
      font.registerFont({ familyName: 'Gochi Hand', familySrc: $rawfile('fonts/GochiHand-Regular.ttf') });
    } catch (e) {
      // 字体注册失败时回退系统字体
    }
    // 官方登录页字体：Outfit（标题）与 Inter（正文）
    try {
      font.registerFont({ familyName: 'Outfit', familySrc: $rawfile('web/_next/static/media/outfit-latin-wght-normal.e96e1529.woff2') });
    } catch (e) {
      // 字体注册失败时回退系统字体
    }
    try {
      font.registerFont({ familyName: 'Inter', familySrc: $rawfile('web/_next/static/media/inter-latin-wght-normal.6c596dfc.woff2') });
    } catch (e) {
      // 字体注册失败时回退系统字体
    }
    this.timer = setInterval(() => {
      this.onTick();
    }, 1000);
    this.init();
  }

  aboutToDisappear(): void {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
    // 取消手表端消息订阅
    if (this.wearSync !== null) {
      this.wearSync.stop();
      this.wearSync = null;
    }
    // 取消订阅握持感知，避免后台持续监听
    if (this.handCb !== null) {
      try {
        motion.off('holdingHandChanged', this.handCb);
      } catch (e) {
        // 设备不支持时忽略
      }
      this.handCb = null;
    }
    if (this.envCbId >= 0 && this.ctx !== null) {
      try {
        this.ctx.getApplicationContext().off('environment', this.envCbId);
      } catch (e) {
        // 取消订阅失败时忽略
      }
      this.envCbId = -1;
    }
  }

  // 返回键优先关闭多选/标签/删除确认等轻量层，避免直接退出当前页面
  onBackPress(): boolean {
    // 应用内官方网页打开时，返回键关闭网页而不是退出应用
    if (this.webPageOpen) {
      this.closeWebAccountPage();
      return true;
    }
    if (this.selDeleteConfirm) {
      this.selDeleteConfirm = false;
      return true;
    }
    if (this.tagOpen) {
      this.tagOpen = false;
      this.tagInput = '';
      return true;
    }
    if (this.sortOpen) {
      this.sortOpen = false;
      return true;
    }
    if (this.selectionMode) {
      this.exitSelection();
      return true;
    }
    if (this.menuId.length > 0) {
      this.menuId = '';
      this.menuConfirm = false;
      return true;
    }
    if (this.fabOpen) {
      this.fabOpen = false;
      return true;
    }
    if (this.searchOpen) {
      this.searchOpen = false;
      return true;
    }
    // 抽屉已不再随页面入栈而关闭，仅在首页（导航栈为空）时用返回键收起
    if (this.drawerOpen && this.pathStack.size() === 0) {
      this.drawerOpen = false;
      return true;
    }
    return false;
  }

  private async init(): Promise<void> {
    this.ctx = getContext(this) as common.Context;
    this.store = new Store(this.ctx, PREF_NAME);
    this.bridge = new Bridge(this.controller);
    try {
      this.appVersion = bundleManager.getBundleInfoForSelfSync(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT).versionName;
    } catch (e) {
      this.appVersion = '';
    }
    // 隐私同意状态要在任何网络请求之前确定，未同意时整个 WebView 都不创建
    this.privacyAccepted = this.store.get(KEY_PRIVACY) === '1';
    this.privacyReady = true;
    // 载入官方多语言词条，并确定当前语言（优先用户选择，否则跟随系统）
    this.loadI18n();
    const savedLocale: string = this.store.get(KEY_LOCALE);
    this.locale = savedLocale.length > 0 ? savedLocale : this.systemLocale();
    this.loadProviderIcons();

    // 首帧前就按屏幕尺寸确定列数/抽屉宽度，避免启动瞬间按单列渲染再跳成多列
    try {
      const d: display.Display = display.getDefaultDisplaySync();
      const dw: number = px2vp(d.width);
      const dh: number = px2vp(d.height);
      if (dw > 0 && dh > 0) {
        this.rootW = dw;
        this.rootH = dh;
        this.stableH = dh;
        this.landscape = dw > dh;
      }
    } catch (e) {
      this.rootW = 0;
      this.rootH = 0;
    }

    // 全屏布局下读取状态栏高度，用于顶栏内边距；同时记录左右/底部安全区
    await this.refreshInsets();

    // 沉浸式材质/光影反馈是否可用（API 26+，模拟器可能不支持，不可用时保留常规样式）
    try {
      this.immersiveOk = uiMaterial.isImmersiveMaterialSupported();
    } catch (e) {
      this.immersiveOk = false;
    }
    // 枚举值在确认支持后才求值：低版本系统上 uiMaterial 为 undefined，提前访问会崩溃
    if (this.immersiveOk) {
      try {
        this.matBtnUltraThin.setStyle(uiMaterial.ImmersiveStyle.ULTRA_THIN);
        this.matBtnThin.setStyle(uiMaterial.ImmersiveStyle.THIN);
        this.matBtnFabChild.setStyle(uiMaterial.ImmersiveStyle.ULTRA_THIN);
        this.matColRegular.setStyle(uiMaterial.ImmersiveStyle.REGULAR);
      } catch (e) {
        this.immersiveOk = false;
      }
    }
    hilog.info(0x0000, TAG, 'immersive=%{public}s', this.immersiveOk.toString());

    // 左右手模式偏好（默认关闭应用锁：仅当用户开启时才要求生物识别）
    this.leftMode = this.store.get(KEY_LEFTMODE) === '1';
    this.appLock = this.store.get(KEY_APPLOCK) === '1';
    this.startHandWatch();

    // 主题与通用偏好
    const tm: string = this.store.get(KEY_THEME);
    this.themeMode = tm.length > 0 ? parseInt(tm, 10) : THEME_SYSTEM;
    this.dark = this.themeMode === THEME_DARK ||
      (this.themeMode === THEME_SYSTEM && this.isSystemDark());
    // 跟随系统主题时，监听系统深浅色切换
    this.startThemeWatch();
    this.bigIcons = this.store.get(KEY_BIG_ICONS) === '1';
    this.compact = this.store.get(KEY_COMPACT) === '1';
    this.copyMinimize = this.store.get(KEY_COPY_MIN) === '1';
    this.hideCodes = this.store.get(KEY_HIDE_CODES) === '1';
    const ldBuf: string = this.store.get(KEY_LOCK_DELAY);
    this.lockDelay = ldBuf.length > 0 ? parseInt(ldBuf, 10) : 0;
    // 首页排序偏好 / 使用频率 / 自定义顺序
    const smBuf: string = this.store.get(KEY_SORT);
    this.sortMode = smBuf.length > 0 ? parseInt(smBuf, 10) : SORT_ISSUER;
    this.tagFilter = this.store.get(KEY_TAG_FILTER);
    this.loadUsage();
    const coBuf: string = this.store.get(KEY_CUSTOM_ORDER);
    if (coBuf.length > 0) {
      try {
        const arr: string[] = JSON.parse(coBuf) as string[];
        if (Array.isArray(arr)) this.customOrder = arr;
      } catch (e) {
        this.customOrder = [];
      }
    }
    this.backupOn = this.store.get(KEY_BACKUP_ON) === '1';
    this.backupPath = this.ctx.filesDir + '/EnteAuthBackups';
    const pwdBlob2: string = this.store.get(KEY_BACKUP_PWD);
    if (pwdBlob2.length > 0) {
      const pwd2: string = await Sealer.unseal(pwdBlob2);
      this.backupPwdCache = pwd2;
      this.backupPwdSet = pwd2.length > 0;
    }
    this.applyStatusBar();

    // 离线缓存（HUKS 加密）优先展示
    const cacheBlob: string = this.store.get(KEY_CACHE);
    if (cacheBlob.length > 0) {
      const txt: string = await Sealer.unseal(cacheBlob);
      if (txt.length > 0) {
        try {
          this.rows = rowsFromPayload(txt);
        } catch (e) {
          this.rows = [];
        }
      }
    }

    // 先完成应用锁校验：有本地缓存时立刻渲染原生列表，不等 WebView 与网络
    this.bioOk = this.appLock ? await Biometrics.verify(this.tr('请验证')) : true;
    if (this.rows.length > 0) {
      this.ensureCodes();
      this.mode = 'ready';
    }

    // 手表端同步：行数据变化时经 Wear Engine 推送；手表侧请求时即时响应；应用锁定期间不外发密钥
    // WearEngine 共享 HSP 仅手机侧存在，须按需动态加载；PC/2in1 上降级为无手表同步，避免启动 abort
    this.wearSync = await loadWearSync(this.ctx, (): OtpRow[] | null => {
      return this.bioOk ? this.rows : null;
    });
    if (this.wearSync !== null) {
      this.wearSync.start();
    }

    // 组装注入脚本：先恢复会话，再注入 libsodium 与桥
    const scripts: Array<ScriptItem> = [];
    let sessTxt: string = '';
    const sessBlob: string = this.store.get(KEY_SESSION);
    if (sessBlob.length > 0) {
      sessTxt = await Sealer.unseal(sessBlob);
    }
    // 迁移旧版明文存储的会话，避免升级后又需重新登录一次
    if (sessTxt.length === 0) {
      const legacy: string = this.store.get('sessionEncryptionKey');
      if (legacy.indexOf('"encryptedData"') >= 0 && legacy.indexOf('"nonce"') >= 0) {
        sessTxt = legacy;
        this.store.put(KEY_SESSION, await Sealer.seal(legacy));
        this.store.del('sessionEncryptionKey');
      }
    }
    if (sessTxt.length > 0) {
      const valid: boolean = sessTxt.indexOf('"encryptedData"') >= 0 &&
        sessTxt.indexOf('"key"') >= 0 &&
        sessTxt.indexOf('"nonce"') >= 0;
      if (valid) {
        // 已有当前页会话不再覆盖（重新登录后 this.scripts 里仍是旧值）；
        // 主动退出登录后带有 __enteSignedOut 标记，禁止把旧会话注入登录页。
        const restore: ScriptItem = {
          script: "try{" +
            "if(!localStorage.getItem('__enteSignedOut')&&!sessionStorage.getItem('encryptionKey')){" +
            "sessionStorage.setItem('encryptionKey'," + JSON.stringify(sessTxt) + ");}}catch(e){}",
          // 只在官方 auth 页面注入，避免污染 accounts 等其它站点的本地存储
          scriptRules: ['https://auth.ente.com'],
        };
        scripts.push(restore);
      } else {
        this.store.del(KEY_SESSION);
      }
    }

    try {
      const decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
      for (const path of EXT_SCRIPTS) {
        const raw: Uint8Array = this.ctx.resourceManager.getRawFileContentSync(path);
        const item: ScriptItem = { script: decoder.decodeToString(raw), scriptRules: ['https://auth.ente.com'] };
        scripts.push(item);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'load ext failed: %{public}s', JSON.stringify(e));
    }
    this.scripts = scripts;
    this.scriptsReady = true;
    // 已登录（有会话）直接进原生列表层：空库先显示占位提示，列表由后台同步填充；
    // 无会话（未登录）直接进原生登录层：两者都不再保持启动图等 WebView 首帧
    if (this.mode !== 'ready' && this.bioOk) {
      this.mode = this.store.get(KEY_SESSION).length > 0 ? 'ready' : 'login';
    }
  }

  private onTick(): void {
    this.nowMs = Date.now();
    // 应用内打开官方账户网页（通行密钥）时，暂停原生轮询，避免对网页做无效调用或误重载
    if (this.webPageOpen) return;
    this.ensureCodes();
    this.verifyTotp();
    this.verifySrp();
    // 页面加载失败（如断网）时定期重试，网络恢复后自动接回
    if (this.scriptsReady && !this.webReady && Date.now() >= this.nextReloadAt) {
      this.nextReloadAt = Date.now() + 5000;
      try {
        this.controller.loadUrl(this.startUrl);
      } catch (e) {
        // Web 组件首帧尚未挂载时 loadUrl 会抛 17100001，此处吞掉并在下一轮重试，避免进程崩溃
      }
    }
    if (this.scriptsReady && this.bioOk && this.webReady) {
      this.pollBridge();
    }
    // 通行密钥登录无深链回跳：停留在验证步骤期间自动轮询进度（3 秒一次）
    if (this.mode === 'login' && this.loginStep === 6 && this.webReady
      && !this.passkeyChecking && Date.now() >= this.passkeyWaitMs) {
      this.passkeyWaitMs = Date.now() + 3000;
      this.checkPasskeyStatus(false);
    }
    // 本地备份：每次启动后自动生成一次加密备份
    if (this.backupOn && !this.backupDone && this.webReady && this.rows.length > 0) {
      this.backupDone = true;
      this.runBackup(true);
    }
  }

  // 一次性自检：用页面的 Web Crypto 独立算一遍，与原生 TOTP 结果比对
  private async verifyTotp(): Promise<void> {
    if (this.totpChecked || this.bridge === null || !this.webReady) return;
    let target: OtpRow | null = null;
    for (const r of this.rows) {
      if (!r.broken && r.secret.length > 0 && r.type !== 'hotp' && r.code.length > 0 && r.step >= 0) {
        target = r;
        break;
      }
    }
    if (target === null) return;
    this.totpChecked = true;
    const args: string = '{"secret":' + JSON.stringify(target.secret) +
      ',"algorithm":"' + target.algorithm + '","digits":' + target.digits +
      ',"step":' + target.step + ',"type":"' + target.type + '"}';
    try {
      const res: BridgeResult = await this.bridge.call('webTotp', args);
      if (!res.ok) {
        // 自检失败不再每秒重试（会造成 hilog 刷屏并触发流控丢日志），仅记录一次
        hilog.error(0x0000, TAG, 'webTotp failed: %{public}s', res.error);
        return;
      }
      const web: string = JSON.parse(res.payload) as string;
      if (web !== target.code) {
        this.notice = this.tr('出了点问题，请重试');
        hilog.error(0x0000, TAG, 'totp mismatch %{public}s %{public}s', web, target.code);
      } else {
        hilog.info(0x0000, TAG, 'totp verified %{public}s', web);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'totp verify error %{public}s', (e as Error).message);
    }
  }

  // 一次性自检：在真实 WebView 环境跑 SRP-4096 golden vector，验证 BigInt/argon2 可用
  private async verifySrp(): Promise<void> {
    if (this.srpSelfChecked || this.bridge === null || !this.webReady) return;
    this.srpSelfChecked = true;
    try {
      const res: BridgeResult = await this.bridge.call('srpSelfTest', '{}');
      if (res.ok) {
        hilog.info(0x0000, TAG, 'srp self test passed');
      } else {
        hilog.error(0x0000, TAG, 'srp self test failed: %{public}s', res.error);
      }
    } catch (e) {
      this.srpSelfChecked = false;
      hilog.error(0x0000, TAG, 'srp self test error: %{public}s', (e as Error).message);
    }
  }

  private async pollBridge(): Promise<void> {
    if (this.polling || this.bridge === null) return;
    this.polling = true;
    try {
      // 页面导航过程中 runJavaScriptExt 可能长时间不返回，超时后放弃本轮，避免永久卡死
      const timeoutPromise: Promise<PollPayload> = new Promise<PollPayload>(
        (resolve: (v: PollPayload) => void, reject: (e: Error) => void) => {
          setTimeout(() => reject(new Error('poll_timeout')), 4000);
        });
      const p: PollPayload = await Promise.race([this.bridge.poll(), timeoutPromise]);
      this.bridge.dispatch(p.results);
      if (this.loggingOut) return;
      const hasKey: boolean = p.probe.hasSessionKey;
      if (p.probe.email.length > 0 && p.probe.email !== this.userEmail) {
        this.userEmail = p.probe.email;
      }
      if (p.results.length > 0) {
        hilog.info(0x0000, TAG, 'poll hasKey=%{public}s res=%{public}d cached=%{public}d',
          hasKey.toString(), p.results.length, p.probe.cached);
      }

      if (hasKey) {
        if (!this.sessionSaved) {
          this.persistSession();
        }
        // 登录成功：原生列表就绪前由登录层自身按钮转圈提示，无需全屏加载圈
        // （全屏覆盖会吞掉 list 失败的错误提示，造成白屏紫圈永转）
        // 恢复流程重置密码步骤（会话已建立但流程未完）暂不取列表，
        // 避免 mode 翻转把重置密码页盖掉
        if (Date.now() >= this.nextListAt
          && !(this.resettingPassword && this.loginStep === 9)) {
          this.nextListAt = Date.now() + 5000;
          this.requestList(true);
        }
      } else if (this.mode === 'ready') {
        // 会话在网页端被撤销：回到原生登录层重新登录
        this.mode = 'login';
        this.webLoading = false;
        this.notice = this.tr('您的会话已过期。请重新登录。');
        this.resetLoginUi();
        this.revealWebPage();
      }
    } catch (e) {
      const msg: string = (e as Error).message;
      if (msg.indexOf('JSON') >= 0 || msg.indexOf('no_bridge') >= 0) {
        // 页面已切到未注入脚本的官方站点（如账户 / 通行密钥页）或正在导航：
        // 跳过本轮即可，绝不能置 webReady=false，否则会被 tick 当成加载失败反复重载
        hilog.info(0x0000, TAG, 'poll skipped: %{public}s', msg);
      } else {
        hilog.error(0x0000, TAG, 'poll err: %{public}s', msg);
      }
    } finally {
      this.polling = false;
    }
  }

  private async persistSession(): Promise<void> {
    if (this.bridge === null || this.store === null || this.sessionSaving) return;
    this.sessionSaving = true;
    try {
      const raw: string = await this.bridge.exec('__enteExt.getSessionKey()');
      if (raw.length > 0 && raw.indexOf('"encryptedData"') >= 0) {
        const sealed: string = await Sealer.seal(raw);
        this.store.put(KEY_SESSION, sealed);
        // 只有真正写盘成功才停止重试：登录过程中主密钥可能晚于探针就绪
        this.sessionSaved = true;
        // 已登录后恢复默认入口，后续重载回到根路径
        this.startUrl = START_URL;
        // 重新登录成功：解除“已退出”标记，下次启动才会恢复会话
        this.bridge.exec("try{localStorage.removeItem('__enteSignedOut');}catch(e){}")
          .catch((e: Error) => {
            hilog.info(0x0000, TAG, 'clear signed-out flag skipped: %{public}s', e.message);
          });
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'persist failed: %{public}s', JSON.stringify(e));
    } finally {
      this.sessionSaving = false;
    }
  }

  // 登录态失效回到网页时，恢复被防闪屏守卫隐藏的页面
  private revealWebPage(): void {
    if (this.bridge === null) return;
    this.bridge.exec("try{document.documentElement.style.visibility='visible';" +
      "document.documentElement.style.background='';}catch(e){}")
      .catch((e: Error) => {
        hilog.info(0x0000, TAG, 'reveal skipped: %{public}s', e.message);
      });
  }

  private async requestList(silent: boolean): Promise<void> {
    if (this.listBusy || this.bridge === null) return;
    if (!this.scriptsReady) return;
    this.listBusy = true;
    try {
      const r: BridgeResult = await this.bridge.call('list', '{}');
      if (!r.ok) throw new Error(r.error);
      // 数据未变化时不再替换 rows，避免列表周期性无谓重建造成闪烁
      if (this.rows.length > 0 && r.payload === this.lastListPayload) {
        this.mode = 'ready';
        this.webLoading = false;
        this.notice = '';
        this.ensureCodes();
        return;
      }
      this.lastListPayload = r.payload;
      const parsed: OtpRow[] = rowsFromPayload(r.payload);
      this.rows = parsed;
      this.mode = 'ready';
      this.webLoading = false;
      this.notice = '';
      this.retried401 = false;
      this.saveCache();
      this.ensureCodes();
    } catch (e) {
      const msg: string = (e as Error).message;
      if (msg.indexOf('http_401') >= 0) {
        hilog.info(0x0000, TAG, 'list 401: %{public}s', msg);
        // 登录过程中令牌会被替换，首次 401 先等一轮再判定，避免误报会话过期
        if (!this.retried401) {
          this.retried401 = true;
          setTimeout(() => {
            this.requestList(silent);
          }, 1500);
          return;
        }
        this.mode = 'login';
        this.webLoading = false;
        this.notice = this.tr('请重新登录');
        this.resetLoginUi();
        this.revealWebPage();
      } else if (this.rows.length > 0) {
        this.mode = 'ready';
        this.webLoading = false;
        this.notice = this.tr('离线模式：显示上次同步的数据');
      } else {
        // 登录后取列表失败（如本地 token 损坏 / 网络错误）：绝不能静默吞掉，
        // 否则加载圈永转；回到登录层并显示原因，用户重登即可覆盖坏状态
        hilog.error(0x0000, TAG, 'list failed: %{public}s', msg);
        this.webLoading = false;
        if (!silent) {
          this.toast(this.tr('出了点问题，请重试'));
        }
        if (this.mode === 'login' && !this.loginBusy && this.loginError.length === 0) {
          // 旧版本写入的本地 token 已损坏等技术性错误，给用户可读的引导文案，
          // 原始错误已在上方 hilog 记录
          this.loginError = this.tr('请重新登录');
          this.revealWebPage();
        }
      }
    } finally {
      this.listBusy = false;
    }
  }

  private async saveCache(): Promise<void> {
    if (this.store === null) return;
    try {
      const json: string = JSON.stringify(this.rows);
      const sealed: string = await Sealer.seal(json);
      this.store.put(KEY_CACHE, sealed);
      // 行数据落盘的同时推送到已连接的手表
      if (this.wearSync !== null) {
        this.wearSync.push();
      }
    } catch (e) {
      // 缓存失败不影响主流程
    }
  }

  // 用服务端返回的最新行替换本地同 id 行（不存在则追加），避免等待下次全量同步
  private upsertRow(r: OtpRow): void {
    const out: OtpRow[] = [];
    let found: boolean = false;
    for (const x of this.rows) {
      if (x.id === r.id) {
        out.push(r);
        found = true;
      } else {
        out.push(x);
      }
    }
    if (!found) out.push(r);
    this.rows = out;
    this.saveCache();
    this.ensureCodes();
  }

  private async ensureCodes(): Promise<void> {
    if (this.codeBusy) return;
    const nowSec: number = this.nowMs / 1000;
    const stale: OtpRow[] = [];
    for (const r of this.rows) {
      if (r.broken || r.secret.length === 0) continue;
      if (r.step !== Math.floor(nowSec / r.period)) stale.push(r);
    }
    if (stale.length === 0) return;
    this.codeBusy = true;
    try {
      for (const r of stale) {
        const step: number = Math.floor(Date.now() / 1000 / r.period);
        const key: Uint8Array = base32Decode(r.secret);
        const code: string = await Totp.generateForCounter(
          key, r.algorithm, r.digits, step, r.type);
        r.step = step;
        r.code = code;
        if (r.type !== 'hotp') {
          r.nextCode = await Totp.generateForCounter(
            key, r.algorithm, r.digits, step + 1, r.type);
        }
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'totp failed: %{public}s', JSON.stringify(e));
    } finally {
      this.codeBusy = false;
    }
    this.rows = this.rows.slice();
  }

  // ---------- 鸿蒙原生能力 ----------

  // 订阅握持感知：左手握持时把悬浮按钮（+）移到左手侧；顶部菜单固定左侧
  private startHandWatch(): void {
    const cb: (status: motion.HoldingHandStatus) => void = (status: motion.HoldingHandStatus) => {
      if (status === motion.HoldingHandStatus.LEFT_HAND_HELD) {
        this.setLeftMode(true, false);
      } else if (status === motion.HoldingHandStatus.RIGHT_HAND_HELD) {
        this.setLeftMode(false, false);
      }
    };
    this.handCb = cb;

    // 设备不具备动作感知能力时直接走手动切换
    if (!canIUse('SystemCapability.MultimodalAwareness.Motion')) {
      this.handAuto = false;
      hilog.info(0x0000, TAG, 'holding hand capability unavailable');
      return;
    }

    // DETECT_GESTURE 属于 user_grant 权限，必须运行时申请，否则真机也不会下发握持事件
    const ctx: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
    const perms: Permissions[] = ['ohos.permission.DETECT_GESTURE'];
    abilityAccessCtrl.createAtManager()
      .requestPermissionsFromUser(ctx, perms)
      .then((res: PermissionRequestResult) => {
        const granted: boolean = res.authResults.length > 0 && res.authResults[0] === 0;
        if (!granted) {
          this.handAuto = false;
          hilog.info(0x0000, TAG, 'holding hand permission denied');
          return;
        }
        try {
          motion.on('holdingHandChanged', cb);
          this.handAuto = true;
          hilog.info(0x0000, TAG, 'holding hand watch enabled');
        } catch (e) {
          // 模拟器等无握持传感器的设备会抛 801，退回手动切换
          this.handAuto = false;
          hilog.info(0x0000, TAG, 'holding hand unsupported: %{public}s', JSON.stringify(e));
        }
      })
      .catch((e: Error) => {
        this.handAuto = false;
        hilog.info(0x0000, TAG, 'holding hand permission failed: %{public}s', e.message);
      });
  }

  // persist=false 用于自动握持识别：只影响本次会话，不写入偏好，重启后回到默认（菜单左、+ 右）
  private setLeftMode(v: boolean, persist: boolean = true): void {
    if (persist && this.store !== null) {
      this.store.put(KEY_LEFTMODE, v ? '1' : '0');
    }
    if (this.leftMode === v) return;
    if (this.handSwitching) return;
    this.handSwitching = true;
    this.playHandSwitch(v);
  }

  // 换手动画：整体先向当前一侧滑出屏幕，再瞬间换到另一侧屏外，最后滑入
  // （与官方跟手控件一致的“出-进”环绕切换，不横穿内容区）
  private playHandSwitch(v: boolean): void {
    const w: number = this.rootW > 0 ? this.rootW : 460;
    const exitX: number = this.leftMode ? -w : w;
    animateTo({
      duration: 110,
      curve: Curve.FastOutLinearIn,
      onFinish: () => {
        // 已在屏幕外：立即换边并把位移翻到另一侧，这一步不做动画（避免看到瞬移过程）
        animateTo({ duration: 0 }, () => {
          this.leftMode = v;
          this.fabShift = v ? -w : w;
        });
        // 下一帧立刻从屏外滑入：快入慢出（起步快、收尾缓）
        setTimeout(() => {
          animateTo({
            duration: 200,
            curve: Curve.LinearOutSlowIn,
            onFinish: () => {
              this.handSwitching = false;
            },
          }, () => {
            this.fabShift = 0;
          });
        }, 16);
      },
    }, () => {
      this.fabShift = exitX;
    });
  }

  // ---------- 主题配色（浅色对齐官方 Flutter 主题，深色为对应夜景） ----------

  private bg(): string {
    return this.dark ? '#000000' : '#FFFFFF';
  }

  private card(): string {
    return this.dark ? '#1C1C1E' : '#F6F6F6';
  }

  private textColor(): string {
    return this.dark ? '#FFFFFF' : '#000000';
  }

  private muted(): string {
    return this.dark ? '#9A9A9A' : '#808080';
  }

  private faint(): string {
    return this.dark ? '#6E6E6E' : '#A6A6A6';
  }

  private primary(): string {
    return this.dark ? '#B368E7' : '#9610D6';
  }

  private pinnedBg(): string {
    return this.dark ? '#2A1033' : '#F9ECFF';
  }

  // 多选选中态背景（官方浅紫底）
  private selectedBg(): string {
    return this.dark ? '#2A1033' : '#F3E8FF';
  }

  private fabBg(): string {
    return this.dark ? '#F2F2F2' : '#282828';
  }

  private fabIcon(): string {
    return this.dark ? '#000000' : '#FFFFFF';
  }

  private divider(): string {
    return this.dark ? '#1FFFFFFF' : '#12000000';
  }

  private inputBg(): string {
    return this.dark ? '#1F1F1F' : '#F5F5F5';
  }

  private chipBg(): string {
    return this.dark ? '#2C2C2E' : '#F2F2F2';
  }

  // 浮层卡片背景：浅色保持官方纯白，深色使用略亮的灰以与遮罩区分
  private elevated(): string {
    return this.dark ? '#1C1C1E' : '#FFFFFF';
  }

  private dangerBg(): string {
    return this.dark ? '#3A1A1A' : '#FDECEA';
  }

  private dangerText(): string {
    return this.dark ? '#FF8A8A' : '#D32F2F';
  }

  private orange(): string {
    return '#FF9500';
  }

  private isSystemDark(): boolean {
    if (this.ctx === null) return false;
    try {
      const cfg = this.ctx.resourceManager.getConfigurationSync();
      return cfg.colorMode === resourceManager.ColorMode.DARK;
    } catch (e) {
      return false;
    }
  }

  // 监听系统配置变化（深浅色切换），同步原生界面与状态栏
  private startThemeWatch(): void {
    if (this.ctx === null || this.envCbId >= 0) return;
    const cb: PageEnvCallback = new PageEnvCallback((config: Configuration) => {
      if (this.themeMode !== THEME_SYSTEM) return;
      const sysDark: boolean = config.colorMode === ConfigurationConstant.ColorMode.COLOR_MODE_DARK;
      if (sysDark === this.dark) return;
      this.dark = sysDark;
      this.applyStatusBar();
      this.refreshCurrentPage();
    });
    try {
      this.envCbId = this.ctx.getApplicationContext().on('environment', cb);
    } catch (e) {
      this.envCbId = -1;
    }
  }

  private setTheme(mode: number): void {
    this.themeMode = mode;
    this.dark = mode === THEME_DARK || (mode === THEME_SYSTEM && this.isSystemDark());
    if (this.store !== null) {
      this.store.put(KEY_THEME, mode.toString());
    }
    this.applyStatusBar();
  }

  // 读取系统栏与挖孔安全区（vp）：旋转后需重新读取，横屏挖孔会换到另一侧
  private async refreshInsets(): Promise<void> {
    if (this.ctx === null) return;
    try {
      const win: window.Window = await window.getLastWindow(this.ctx);
      const sys: window.AvoidArea = await win.getAvoidArea(window.AvoidAreaType.TYPE_SYSTEM);
      let cutL: number = 0;
      let cutR: number = 0;
      try {
        const cut: window.AvoidArea = await win.getAvoidArea(window.AvoidAreaType.TYPE_CUTOUT);
        cutL = px2vp(cut.leftRect.width);
        cutR = px2vp(cut.rightRect.width);
      } catch (e) {
        cutL = 0;
        cutR = 0;
      }
      this.topInset = px2vp(sys.topRect.height);
      this.safeB = px2vp(sys.bottomRect.height);
      this.safeL = Math.max(px2vp(sys.leftRect.width), cutL);
      this.safeR = Math.max(px2vp(sys.rightRect.width), cutR);
    } catch (e) {
      this.topInset = 0;
      this.safeL = 0;
      this.safeR = 0;
      this.safeB = 0;
    }
  }

  private applyStatusBar(): void {
    if (this.ctx === null) return;
    window.getLastWindow(this.ctx).then((win: window.Window) => {
      win.setWindowSystemBarProperties({
        statusBarColor: '#00000000',
        statusBarContentColor: this.dark ? '#FFFFFF' : '#000000',
        navigationBarColor: '#00000000',
        navigationBarContentColor: this.dark ? '#FFFFFF' : '#000000',
      });
    }).catch((e: Error) => {
      hilog.error(0x0000, TAG, 'statusBar failed %{public}s', e.message);
    });
  }

  private onLoginBusyChange(): void {
    if (this.ctx === null) return;
    window.getLastWindow(this.ctx).then((win: window.Window) => {
      win.setWindowKeepScreenOn(this.loginBusy);
    }).catch((e: Error) => {
      hilog.error(0x0000, TAG, 'keepScreenOn failed %{public}s', e.message);
    });
    if (this.busyTimerId >= 0) {
      clearInterval(this.busyTimerId);
      this.busyTimerId = -1;
    }
    if (this.loginBusy) {
      this.busySec = 0;
      this.busyTimerId = setInterval(() => {
        this.busySec++;
      }, 1000);
    }
  }

  // ---------- 交互 ----------

  private visibleRows(): OtpRow[] {
    return this.filterRows(false);
  }

  // 首页标签分组：聚合未删除条目上的标签，去重后按字母序（对齐官方 getAllTags）
  private allTags(): string[] {
    const set: Set<string> = new Set<string>();
    for (const r of this.rows) {
      if (r.trashed) continue;
      for (const t of r.tags) {
        if (t.length > 0) set.add(t);
      }
    }
    const out: string[] = [];
    set.forEach((t: string) => out.push(t));
    out.sort((a: string, b: string) => a < b ? -1 : (a > b ? 1 : 0));
    return out;
  }

  // 标签被删除/改名后自动回落到「全部」
  private activeTag(): string {
    const t: string = this.tagFilter;
    if (t.length === 0) return '';
    return this.allTags().indexOf(t) >= 0 ? t : '';
  }

  private hasCodes(): boolean {
    for (const r of this.rows) {
      if (!r.trashed) return true;
    }
    return false;
  }

  private setTagFilter(t: string): void {
    this.tagFilter = this.activeTag() === t ? '' : t;
    if (this.store !== null) this.store.put(KEY_TAG_FILTER, this.tagFilter);
  }

  private openTagMenu(t: string): void {
    this.tagMenuTag = t;
    this.tagMenuOpen = true;
  }

  private openTagEdit(): void {
    this.tagEditText = this.tagMenuTag;
    this.tagMenuOpen = false;
    this.tagEditOpen = true;
  }

  // 重命名标签：批量更新所有包含该标签的条目（对齐官方 editTag）
  private async saveTagEdit(): Promise<void> {
    const oldTag: string = this.tagMenuTag;
    const newTag: string = this.tagEditText.trim();
    this.tagEditOpen = false;
    if (newTag.length === 0 || newTag === oldTag || this.bridge === null) return;
    const bridge: Bridge = this.bridge;
    for (const r of this.rows) {
      if (r.tags.indexOf(oldTag) < 0) continue;
      const tags: string[] = [];
      for (const t of r.tags) {
        if (t !== oldTag) tags.push(t);
      }
      if (tags.indexOf(newTag) < 0) tags.push(newTag);
      try {
        await bridge.call('setTags',
          '{"id":' + JSON.stringify(r.id) + ',"tags":' + JSON.stringify(tags) + '}');
        r.tags = tags;
      } catch (e) {
        hilog.error(0x0000, TAG, 'rename tag failed %{public}s', (e as Error).message);
      }
    }
    if (this.tagFilter === oldTag) this.tagFilter = newTag;
    if (this.store !== null) this.store.put(KEY_TAG_FILTER, this.tagFilter);
    this.rows = this.rows.slice();
  }

  // 删除标签：从所有条目上移除（对齐官方 showDeleteTagDialog）
  private async deleteTag(): Promise<void> {
    const tag: string = this.tagMenuTag;
    this.tagDeleteOpen = false;
    if (this.bridge === null) return;
    const bridge: Bridge = this.bridge;
    for (const r of this.rows) {
      if (r.tags.indexOf(tag) < 0) continue;
      const tags: string[] = [];
      for (const t of r.tags) {
        if (t !== tag) tags.push(t);
      }
      try {
        await bridge.call('setTags',
          '{"id":' + JSON.stringify(r.id) + ',"tags":' + JSON.stringify(tags) + '}');
        r.tags = tags;
      } catch (e) {
        hilog.error(0x0000, TAG, 'delete tag failed %{public}s', (e as Error).message);
      }
    }
    if (this.tagFilter === tag) this.tagFilter = '';
    if (this.store !== null) this.store.put(KEY_TAG_FILTER, this.tagFilter);
    this.rows = this.rows.slice();
  }

  private trashRows(): OtpRow[] {
    return this.filterRows(true);
  }

  private filterRows(trashed: boolean): OtpRow[] {
    const q: string = this.query.trim().toLowerCase();
    const tag: string = this.activeTag();
    const out: OtpRow[] = [];
    for (const r of this.rows) {
      if (r.trashed !== trashed) continue;
      if (tag.length > 0 && r.tags.indexOf(tag) < 0) continue;
      if (q.length > 0) {
        const hay: string = (r.issuer + ' ' + r.account + ' ' + r.note).toLowerCase();
        if (hay.indexOf(q) < 0) continue;
      }
      out.push(r);
    }
    out.sort((a: OtpRow, b: OtpRow) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      if (this.sortMode === SORT_ACCOUNT) {
        const aa: string = a.account.toLowerCase() + a.issuer.toLowerCase();
        const ab: string = b.account.toLowerCase() + b.issuer.toLowerCase();
        return aa < ab ? -1 : (aa > ab ? 1 : 0);
      }
      if (this.sortMode === SORT_FREQUENT) {
        const ca: number = this.usageCount.get(a.id) ?? 0;
        const cb: number = this.usageCount.get(b.id) ?? 0;
        if (ca !== cb) return cb - ca;
      }
      if (this.sortMode === SORT_RECENT) {
        const ta: number = this.usageLast.get(a.id) ?? 0;
        const tb: number = this.usageLast.get(b.id) ?? 0;
        if (ta !== tb) return tb - ta;
      }
      if (this.sortMode === SORT_CUSTOM) {
        const ia: number = this.customOrder.indexOf(a.id);
        const ib: number = this.customOrder.indexOf(b.id);
        const ra: number = ia < 0 ? 1e9 : ia;
        const rb: number = ib < 0 ? 1e9 : ib;
        if (ra !== rb) return ra - rb;
      }
      const ka: string = (a.issuer + a.account).toLowerCase();
      const kb: string = (b.issuer + b.account).toLowerCase();
      return ka < kb ? -1 : (ka > kb ? 1 : 0);
    });
    return out;
  }

  // ---------- 排序 / 使用统计 ----------

  private loadUsage(): void {
    this.usageCount.clear();
    this.usageLast.clear();
    if (this.store === null) return;
    const raw: string = this.store.get(KEY_USAGE);
    if (raw.length === 0) return;
    for (const line of raw.split('\n')) {
      const parts: string[] = line.split('|');
      if (parts.length < 3) continue;
      const c: number = parseInt(parts[1], 10);
      const t: number = parseInt(parts[2], 10);
      if (parts[0].length === 0 || isNaN(c) || isNaN(t)) continue;
      this.usageCount.set(parts[0], c);
      this.usageLast.set(parts[0], t);
    }
  }

  private saveUsage(): void {
    if (this.store === null) return;
    const lines: string[] = [];
    this.usageCount.forEach((c: number, id: string) => {
      const t: number = this.usageLast.get(id) ?? 0;
      lines.push(id + '|' + c + '|' + t);
    });
    this.store.put(KEY_USAGE, lines.join('\n'));
  }

  // 复制即计入使用频率与最近使用
  private trackUsage(id: string): void {
    const c: number = (this.usageCount.get(id) ?? 0) + 1;
    this.usageCount.set(id, c);
    this.usageLast.set(id, Date.now());
    this.usageRev++;
    this.saveUsage();
  }

  private setSortMode(v: number): void {
    this.sortMode = v;
    if (this.store !== null) this.store.put(KEY_SORT, v.toString());
    if (v === SORT_CUSTOM) this.ensureCustomOrder();
  }

  // 自定义顺序：补齐新条目、移除已删除条目
  private ensureCustomOrder(): void {
    const order: string[] = [];
    for (const prev of this.customOrder) {
      for (const r of this.rows) {
        if (r.id === prev && !r.trashed) {
          order.push(prev);
          break;
        }
      }
    }
    for (const r of this.rows) {
      if (!r.trashed && order.indexOf(r.id) < 0) order.push(r.id);
    }
    this.customOrder = order;
    if (this.store !== null) this.store.put(KEY_CUSTOM_ORDER, JSON.stringify(order));
  }

  private moveCustom(id: string, delta: number): void {
    const cur: string[] = this.customOrder.slice();
    const i: number = cur.indexOf(id);
    if (i < 0) return;
    const j: number = i + delta;
    if (j < 0 || j >= cur.length) return;
    const tmp: string = cur[i];
    cur[i] = cur[j];
    cur[j] = tmp;
    this.customOrder = cur;
    if (this.store !== null) this.store.put(KEY_CUSTOM_ORDER, JSON.stringify(cur));
  }

  // 抽屉宽度（vp）：占窗口 82%，上限 420（横屏同样限制，避免铺满整屏）
  private drawerWidth(): number {
    const w: number = this.rootW > 0 ? this.rootW : 394;
    return Math.min(w * 0.82, 420);
  }

  // 首页列数：按窗口宽度自适应，手机竖屏 1 列、手机横屏 2 列、平板 3 列（对齐官方横屏多列）
  private gridColumns(): number {
    if (this.rootW >= 900) return 3;
    if (this.rootW >= 560) return 2;
    return 1;
  }

  private columnsTemplate(): string {
    const n: number = this.gridColumns();
    let s: string = '1fr';
    for (let i = 1; i < n; i++) s += ' 1fr';
    return s;
  }

  private remain(r: OtpRow): number {
    const sec: number = Math.floor(this.nowMs / 1000);
    return r.period - (sec % r.period);
  }

  private formatCode(code: string): string {
    if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
    if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
    return code;
  }

  // 隐藏验证码（官方“隐藏验证码”开关：双击卡片临时显示）
  private displayCode(r: OtpRow): string {
    if (r.code.length === 0) return '------';
    if (this.hideCodes && this.revealedId !== r.id) {
      return r.code.length === 8 ? '•••• ••••' : '••• •••';
    }
    return this.formatCode(r.code);
  }

  // 下一个验证码同样受“隐藏验证码”保护
  private displayNextCode(r: OtpRow): string {
    if (r.nextCode.length === 0) return '';
    if (this.hideCodes && this.revealedId !== r.id) {
      return r.nextCode.length === 8 ? '•••• ••••' : '••• •••';
    }
    return this.formatCode(r.nextCode);
  }

  private titleOf(r: OtpRow): string {
    if (r.issuer.length > 0) return r.issuer;
    return r.account;
  }

  // ---------- 官方图标映射（custom-icons，与服务端无关，完全本地） ----------

  private providerKey(provider: string): string {
    return provider.split(' ').join('').toLowerCase();
  }

  private loadProviderIcons(): void {
    if (this.ctx === null) return;
    try {
      const raw: Uint8Array = this.ctx.resourceManager.getRawFileContentSync('providers/custom-icons.json');
      const decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
      const file: ProviderIconsFile = JSON.parse(decoder.decodeToString(raw)) as ProviderIconsFile;
      const map: Map<string, ProviderIcon> = new Map<string, ProviderIcon>();
      for (const e of file.icons) {
        const key: string = this.providerKey(e.title);
        const slug: string = (e.slug !== undefined && e.slug.length > 0) ? e.slug : key;
        const hex: string = e.hex !== undefined ? e.hex : '';
        const icon: ProviderIcon = { slug: slug, hex: hex };
        map.set(key, icon);
        if (e.altNames !== undefined) {
          for (const n of e.altNames) map.set(this.providerKey(n), icon);
        }
      }
      this.providerIcons = map;
    } catch (e) {
      hilog.warn(0x0000, TAG, 'load provider icons failed');
    }
  }

  private iconFor(provider: string): ProviderIcon | null {
    if (provider.length === 0) return null;
    const key: string = this.providerKey(provider);
    let hit: ProviderIcon | undefined = this.providerIcons.get(key);
    if (hit !== undefined) return hit;
    // 与服务端一致：形如 "GitHub (work)" / "Google.cloud" 时取分隔符前的名称
    for (const sep of ['(', '.']) {
      const idx: number = key.indexOf(sep);
      if (idx > 0) {
        const sub: ProviderIcon | undefined = this.providerIcons.get(key.substring(0, idx));
        if (sub !== undefined) return sub;
      }
    }
    return null;
  }

  private avatarColorOf(provider: string): string {
    let h: number = 0;
    for (let i = 0; i < provider.length; i++) {
      h = (h * 31 + provider.charCodeAt(i)) % 2147483647;
    }
    return AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length];
  }

  private avatarLetterOf(provider: string): string {
    const t: string = provider.trim();
    return t.length > 0 ? t.charAt(0).toUpperCase() : '?';
  }

  private async copyCode(r: OtpRow): Promise<void> {
    if (r.code.length === 0) return;
    this.trackUsage(r.id);
    const data: pasteboard.PasteData = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, r.code);
    await pasteboard.getSystemPasteboard().setData(data);
    this.toast(this.tr('代码已复制到剪贴板'));
    this.minimizeIfNeeded();
  }

  private async copyRecoveryKey(): Promise<void> {
    if (this.recoveryWords.length === 0) return;
    try {
      const data: pasteboard.PasteData =
        pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, this.recoveryWords);
      await pasteboard.getSystemPasteboard().setData(data);
      this.toast(this.tr('恢复密钥已复制到剪贴板'));
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    }
  }

  // 调起系统分享面板；不支持时返回 false，由调用方退回复制到剪贴板
  private async systemShareText(text: string, title: string): Promise<boolean> {
    try {
      const data: systemShare.SharedData = new systemShare.SharedData({
        utd: 'general.plain-text',
        content: text,
        title: title,
      });
      const controller: systemShare.ShareController = new systemShare.ShareController(data);
      const abilityCtx: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      await controller.show(abilityCtx, {});
      return true;
    } catch (e) {
      return false;
    }
  }

  private async shareRecoveryKey(): Promise<void> {
    if (this.recoveryWords.length === 0) return;
    if (await this.systemShareText(this.recoveryWords, this.tr('恢复密钥'))) return;
    await this.copyRecoveryKey();
  }

  private async copyNextCode(r: OtpRow): Promise<void> {
    if (r.nextCode.length === 0) return;
    this.trackUsage(r.id);
    const data: pasteboard.PasteData = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, r.nextCode);
    await pasteboard.getSystemPasteboard().setData(data);
    this.toast(this.tr('已将下一个代码复制到剪贴板'));
    this.minimizeIfNeeded();
  }

  // 「复制后最小化」：复制验证码后自动退到后台，方便粘贴到其他应用
  private minimizeIfNeeded(): void {
    if (!this.copyMinimize || this.ctx === null) return;
    window.getLastWindow(this.ctx).then((win: window.Window) => {
      win.minimize().catch((e: Error) => {
        hilog.error(0x0000, TAG, 'minimize failed %{public}s', e.message);
      });
    }).catch((e: Error) => {
      hilog.error(0x0000, TAG, 'minimize window failed %{public}s', e.message);
    });
  }

  // 退出登录：对齐官方 accountLogout —— 注销远端会话，清空网页端 sessionStorage /
  // localStorage 与 IndexedDB 中的 auth token，再回到登录页。
  // 只删 token 会残留 user / keyAttributes，下次登录会走错分支并提示“出错了”。
  private async logout(): Promise<void> {
    // 登出/删除账户后直接回原生登录页，不再经过启动图
    this.mode = 'login';
    this.resetLoginUi();
    this.loggingOut = true;
    if (this.bridge !== null) {
      const cleanup: Promise<BridgeResult> = this.bridge.call('logout', '{}');
      const guard: Promise<BridgeResult> = new Promise<BridgeResult>(
        (resolve: (r: BridgeResult) => void) => {
          setTimeout(() => resolve(new BridgeResult()), 8000);
        });
      try {
        await Promise.race([cleanup, guard]);
      } catch (e) {
        hilog.error(0x0000, TAG, 'logout cleanup failed: %{public}s', (e as Error).message);
      }
    }
    if (this.store !== null) {
      this.store.del(KEY_SESSION);
      this.store.del(KEY_CACHE);
    }
    this.rows = [];
    this.sessionSaved = false;
    this.totpChecked = false;
    this.notice = '';
    this.userEmail = '';
    this.webReady = false;
    this.loadFailed = false;
    // 直接进入登录页，并在页面就绪前保持启动图遮罩，避免闪现其他网页内容
    this.startUrl = LOGIN_URL;
    this.nextReloadAt = Date.now() + 15000;
    try {
      this.controller.loadUrl(LOGIN_URL);
    } catch (e) {
      // 页面可能未就绪，下次 tick 会自动重载
    }
    this.loggingOut = false;
  }

  private resetLoginUi(): void {
    this.loginStep = 0;
    this.loginPwd = '';
    this.loginCode = '';
    this.loginBusy = false;
    this.loginError = '';
    this.loginPwdVisible = false;
    this.loginFocus = '';
    this.otpFocusIdx = -1;
    this.loginPwdUnlock = false;
    this.totpFromSrp = false;
    this.otpPurpose = '';
    this.setPwd = '';
    this.setPwdConfirm = '';
    this.signupMnemonic = '';
    this.passkeyUrl = '';
    this.passkeyTotpAvailable = false;
    this.passkeyChecking = false;
    this.passkeyWaitMs = 0;
    this.signupPwd = '';
    this.signupPwdConfirm = '';
    this.tosAccepted = true;
    this.resettingPassword = false;
    this.recoveryKeyInput = '';
  }

  // 密码强度估算（对齐官方 password_strength 包的熵估算，归一化到 0..1）
  private pwStrength(pw: string): number {
    if (pw.length === 0) {
      return 0;
    }
    let pool: number = 0;
    if (/[a-z]/.test(pw)) {
      pool += 26;
    }
    if (/[A-Z]/.test(pw)) {
      pool += 26;
    }
    if (/[0-9]/.test(pw)) {
      pool += 10;
    }
    if (/[^a-zA-Z0-9]/.test(pw)) {
      pool += 33;
    }
    if (pool === 0) {
      pool = 1;
    }
    return Math.min(1, pw.length * Math.log2(pool) / 100);
  }

  private pwStrengthLabel(v: number): string {
    if (v > 0.7) {
      return this.tr('强');
    }
    if (v >= 0.4) {
      return this.tr('中等');
    }
    return this.tr('弱');
  }

  private pwStrengthColor(v: number): string {
    if (v > 0.7) {
      return '#22C55E';
    }
    if (v >= 0.4) {
      return '#FF9F43';
    }
    return '#F63A3A';
  }

  // 密码强度文案（对齐官方 passwordStrength 词条：整行按强度着色）
  private pwStrengthText(pw: string): string {
    return this.tr('密码强度： {passwordStrengthValue}')
      .replace('{passwordStrengthValue}', this.pwStrengthLabel(this.pwStrength(pw)));
  }

  private loginInputValid(): boolean {
    if (this.loginStep === 0) {
      return this.loginEmail.trim().length > 3;
    }
    if (this.loginStep === 1) {
      return this.loginPwd.length > 0;
    }
    if (this.loginStep === 2 || this.loginStep === 3) {
      return this.loginCode.trim().length >= 6;
    }
    if (this.loginStep === 4 || this.loginStep === 9) {
      return this.setPwd.length >= 8 && this.setPwd === this.setPwdConfirm
        && this.pwStrength(this.setPwd) >= 0.4;
    }
    if (this.loginStep === 8) {
      return this.recoveryKeyInput.trim().length >= 6;
    }
    if (this.loginStep === 5 || this.loginStep === 6) {
      return true;
    }
    // 步骤 7（注册入口）
    return this.loginEmail.trim().length > 3 && this.signupPwd.length >= 8
      && this.signupPwd === this.signupPwdConfirm && this.pwStrength(this.signupPwd) >= 0.4;
  }

  private submitLoginStep(): void {
    if (this.loginStep === 0) {
      this.submitLoginEmail();
    } else if (this.loginStep === 1) {
      if (this.loginPwdUnlock) {
        this.submitLoginUnlock();
      } else {
        this.submitLoginPassword();
      }
    } else if (this.loginStep === 2) {
      this.submitLoginTotp();
    } else if (this.loginStep === 3) {
      this.submitOtp();
    } else if (this.loginStep === 4) {
      this.submitSetPassword();
    } else if (this.loginStep === 5) {
      this.submitSignupFinish();
    } else if (this.loginStep === 6) {
      if (this.passkeyUrl.length > 0) {
        this.copyPasskeyUrl();
      } else {
        this.refreshPasskeyUrl();
      }
    } else if (this.loginStep === 7) {
      this.submitSignupEntry();
    } else if (this.loginStep === 8) {
      this.submitRecoveryKey();
    } else if (this.loginStep === 9) {
      this.submitResetPassword();
    }
  }

  // 协议引擎错误码 → 用户可读文案
  private loginErrorText(err: string): string {
    hilog.error(0x0000, TAG, 'login raw error: %{public}s', err);
    if (err === 'incorrect_password') {
      return this.tr('密码错误');
    }
    if (err === 'incorrect_code') {
      return this.tr('代码错误');
    }
    if (err === 'code_expired') {
      return this.tr('您的验证码已过期');
    }
    if (err === 'session_expired' || err === 'no_login_ctx') {
      return this.tr('会话已过期');
    }
    if (err === 'not_registered') {
      return this.tr('该电子邮件未注册。');
    }
    if (err === 'signup_incomplete') {
      return this.tr('账户设置未完成。请创建账户以完成设置。');
    }
    if (err === 'already_registered') {
      return this.tr('此电子邮件已被使用');
    }
    if (err === 'weak_device') {
      return this.tr('设备不安全');
    }
    if (err === 'rate_limited') {
      return this.tr('出了点问题，请重试');
    }
    if (err === 'invalid_recovery_key') {
      return this.tr('您输入的恢复密钥无效。请确保它包含 24 个单词，并检查每个单词的拼写。\n\n如果您输入的是旧版恢复码，请确保其长度为 64 个字符，并检查其中每个字符。');
    }
    if (err === 'incorrect_recovery_key') {
      return this.tr('您输入的恢复密钥不正确');
    }
    if (err === 'no_recovery_key') {
      return this.tr('该账户未配置恢复密钥');
    }
    if (err.indexOf('http_') === 0) {
      return this.tr('网络错误。请检查您的网络连接。') + ' (' + err + ')';
    }
    return this.tr('出了点问题，请重试') + ' (' + err + ')';
  }

  // 登录/注册已在服务端完成：保持转圈，等 pollBridge 探测到会话后自动进入列表
  private waitLoginDone(timeoutMs: number): void {
    setTimeout(() => {
      if (this.mode === 'login' && this.loginBusy) {
        this.loginBusy = false;
        this.loginError = this.tr('网络错误。请检查您的网络连接。');
      }
    }, timeoutMs);
  }

  // 登录响应分流（对应 ext classifyAuthResponse 的 next）：
  // done → 等待会话生效；passkey → 通行密钥步骤；twofactor → 验证码步骤；
  // unlock → 输密码解锁；setpassword → 设置密码。返回是否已进入完成等待
  private handleLoginNext(p: LoginNextPayload): boolean {
    const next: string = p.next !== undefined && p.next.length > 0
      ? p.next : (p.done === true ? 'done' : '');
    if (next === 'done') {
      this.waitLoginDone(30000);
      return true;
    }
    if (next === 'passkey') {
      this.enterPasskeyStep();
      return false;
    }
    if (next === 'twofactor') {
      this.loginCode = '';
      this.loginStep = 2;
      return false;
    }
    if (next === 'unlock') {
      // 忘记密码恢复流程：不解锁，改走恢复密钥步骤（ctx.otpAuth 已在 ext 侧保存）
      if (this.resettingPassword) {
        this.recoveryKeyInput = '';
        this.loginStep = 8;
        return false;
      }
      this.loginPwdUnlock = true;
      this.loginPwd = '';
      this.loginKekSalt = p.kekSalt !== undefined ? p.kekSalt : '';
      this.loginOpsLimit = p.opsLimit !== undefined ? p.opsLimit : 0;
      this.loginMemLimit = p.memLimit !== undefined ? p.memLimit : 0;
      this.loginStep = 1;
      return false;
    }
    if (next === 'setpassword') {
      this.setPwd = '';
      this.setPwdConfirm = '';
      this.loginStep = 4;
      return false;
    }
    this.loginError = this.tr('出了点问题，请重试');
    return false;
  }

  // 发送邮箱验证码并进入验证码步骤（调用方需已置 loginBusy 并负责复位）
  private async sendOttAndEnterStep(purpose: string): Promise<void> {
    if (this.bridge === null) {
      return;
    }
    try {
      const res: BridgeResult = await this.bridge.call('sendOtt',
        '{"email":' + JSON.stringify(this.loginEmail) + ',"purpose":"' + purpose + '"}');
      if (!res.ok) {
        this.loginError = this.loginErrorText(res.error);
        return;
      }
      this.otpPurpose = purpose;
      this.totpFromSrp = false;
      this.loginCode = '';
      this.loginError = '';
      this.loginStep = 3;
      this.otpFocusIdx = -1;
      this.toast(this.tr('@weHaveSentCode').replace('{email}', this.loginEmail));
    } catch (e) {
      hilog.error(0x0000, TAG, 'sendOtt exception: %{public}s', (e as Error).message);
      this.loginError = this.tr('网络错误。请检查您的网络连接。');
    }
  }

  // 原生 C++ Argon2id 派生 KEK（与官方客户端 KDF 等价：
  // Argon2id v0x13, p=1, dkLen=32, libsodium 兼容参数）。失败抛错由调用方处理
  private async deriveKekNative(password: string, kekSalt: string,
    opsLimit: number, memLimit: number): Promise<string> {
    return await deriveKek(password, kekSalt, opsLimit, memLimit);
  }

  // 当前登录流程是否已持有可用的 KDF 参数
  private hasKdfParams(): boolean {
    return this.loginKekSalt.length > 0 && this.loginOpsLimit >= 1
      && this.loginMemLimit >= 134217728;
  }

  // 未登录时登录层先行渲染，WebView 协议引擎仍在后台加载：
  // 提交前等待其就绪，超时由调用方按网络错误提示
  private async waitWebReady(maxMs: number): Promise<boolean> {
    const t0: number = Date.now();
    while (!this.webReady && Date.now() - t0 < maxMs) {
      await new Promise<void>((resolve: (v: void) => void) => {
        setTimeout(resolve, 100);
      });
    }
    return this.webReady;
  }

  // 启动期原生 Argon2id 自测（宿主机已与 @noble/hashes、libsodium 交叉验证的
  // 两组向量），结果记 hilog，不阻塞登录流程
  private async runArgon2SelfTest(): Promise<void> {
    const t0: number = Date.now();
    try {
      const r: string = await argon2SelfTest();
      hilog.info(0x0000, TAG, 'argon2 selftest %{public}s in %{public}dms', r, Date.now() - t0);
    } catch (e) {
      hilog.error(0x0000, TAG, 'argon2 selftest exception: %{public}s', (e as Error).message);
    }
  }

  // 步骤 0：提交邮箱，查询 SRP 属性；无 SRP / 启用邮箱 MFA 的账户改走邮箱验证码登录
  private async submitLoginEmail(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    const email: string = this.loginEmail.trim();
    const at: number = email.indexOf('@');
    if (at < 1 || email.indexOf('.', at) <= at) {
      this.loginError = this.tr('请输入有效的电子邮件地址。');
      return;
    }
    this.loginBusy = true;
    this.loginError = '';
    try {
      // 登录层已先行展示，WebView 引擎可能仍在加载：先等就绪再发 loginPrepare
      if (!await this.waitWebReady(15000)) {
        this.loginError = this.tr('网络错误。请检查您的网络连接。');
        return;
      }
      const res: BridgeResult = await this.bridge.call('loginPrepare', '{"email":' + JSON.stringify(email) + '}');
      if (res.ok) {
        const p: LoginPreparePayload = JSON.parse(res.payload) as LoginPreparePayload;
        hilog.info(0x0000, TAG, 'loginPrepare ok mfa=%{public}s', p.isEmailMFAEnabled.toString());
        this.loginEmail = email;
        this.loginKekSalt = p.kekSalt !== undefined ? p.kekSalt : '';
        this.loginOpsLimit = p.opsLimit !== undefined ? p.opsLimit : 0;
        this.loginMemLimit = p.memLimit !== undefined ? p.memLimit : 0;
        if (p.isEmailMFAEnabled) {
          // 已启用邮箱 MFA：密码登录不可用，改发邮箱验证码
          await this.sendOttAndEnterStep('login');
          return;
        }
        this.loginPwdUnlock = false;
        this.totpFromSrp = false;
        this.loginStep = 1;
      } else {
        hilog.info(0x0000, TAG, 'loginPrepare failed: %{public}s', res.error);
        if (res.error === 'no_srp' || res.error === 'bad_attributes') {
          // 账户无 SRP 属性（仅验证码登录 / 注册未完成）：直接发送验证码
          this.loginEmail = email;
          await this.sendOttAndEnterStep('login');
          return;
        }
        this.loginError = this.loginErrorText(res.error);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'loginPrepare exception: %{public}s', (e as Error).message);
      this.loginError = this.tr('网络错误。请检查您的网络连接。');
    } finally {
      this.loginBusy = false;
    }
  }

  // 步骤 1：提交密码（原生 Argon2id 派生 kek → SRP-4096 建会话），按需进入 2FA / 通行密钥
  private async submitLoginPassword(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (!this.hasKdfParams()) {
      // loginPrepare 未下发 KDF 参数（流程被重置/异常）：回邮箱步骤重来
      this.loginError = this.tr('会话已过期');
      this.loginStep = 0;
      return;
    }
    this.loginBusy = true;
    this.loginError = '';
    let kekB64: string = '';
    const t0: number = Date.now();
    try {
      kekB64 = await this.deriveKekNative(this.loginPwd, this.loginKekSalt, this.loginOpsLimit, this.loginMemLimit);
      hilog.info(0x0000, TAG, 'native argon2 kek derived in %{public}dms', Date.now() - t0);
    } catch (e) {
      hilog.error(0x0000, TAG, 'native argon2 failed after %{public}dms: %{public}s',
        Date.now() - t0, (e as Error).message);
      this.loginBusy = false;
      this.loginError = this.loginErrorText('weak_device');
      return;
    }
    let done: boolean = false;
    try {
      const res: BridgeResult = await this.bridge.call('loginPassword',
        '{"kekB64":' + JSON.stringify(kekB64) + '}', 180000);
      if (res.ok) {
        const p: LoginAuthPayload = JSON.parse(res.payload) as LoginAuthPayload;
        hilog.info(0x0000, TAG, 'loginPassword ok 2fa=%{public}s passkey=%{public}s',
          (p.needs2FA === true).toString(), (p.needsPasskey === true).toString());
        if (p.needsPasskey === true) {
          // 通行密钥二次验证（ext 已记录会话与 twoFactor 备用会话）
          this.totpFromSrp = true;
          await this.enterPasskeyStep();
        } else if (p.needs2FA === true) {
          this.totpFromSrp = true;
          this.loginCode = '';
          this.loginStep = 2;
        } else {
          // 登录完成：保持按钮转圈，等 pollBridge 探测到会话后自动进入列表
          done = true;
        }
      } else {
        hilog.info(0x0000, TAG, 'loginPassword failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'loginPassword exception: %{public}s', (e as Error).message);
      // 桥超时/异常时 ext 侧操作可能仍在执行并稍后自行完成（慢网络下 SRP 较慢），
      // 不立即报错：保持转圈延迟复查，若期间轮询探测到会话并进入列表则不再提示
      setTimeout(() => {
        if (this.mode === 'login' && this.loginBusy) {
          this.loginBusy = false;
          this.loginError = this.tr('网络错误。请检查您的网络连接。');
        }
      }, 8000);
      return;
    }
    if (!done) {
      this.loginBusy = false;
      return;
    }
    this.waitLoginDone(30000);
  }

  // 步骤 1（OTP 登录后解锁）：原生 Argon2id 派生 kek 解密 master key 完成登录
  private async submitLoginUnlock(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (!this.hasKdfParams()) {
      // unlock 分流未携带 KDF 参数（流程被重置/异常）：回邮箱步骤重来
      this.loginError = this.tr('会话已过期');
      this.loginStep = 0;
      return;
    }
    this.loginBusy = true;
    this.loginError = '';
    let kekB64: string = '';
    const t0: number = Date.now();
    try {
      kekB64 = await this.deriveKekNative(this.loginPwd, this.loginKekSalt, this.loginOpsLimit, this.loginMemLimit);
      hilog.info(0x0000, TAG, 'native argon2 kek derived in %{public}dms', Date.now() - t0);
    } catch (e) {
      hilog.error(0x0000, TAG, 'native argon2 failed after %{public}dms: %{public}s',
        Date.now() - t0, (e as Error).message);
      this.loginBusy = false;
      this.loginError = this.loginErrorText('weak_device');
      return;
    }
    let done: boolean = false;
    try {
      const res: BridgeResult = await this.bridge.call('unlockWithPassword',
        '{"kekB64":' + JSON.stringify(kekB64) + '}', 180000);
      if (res.ok) {
        hilog.info(0x0000, TAG, 'unlockWithPassword ok');
        done = true;
      } else {
        hilog.info(0x0000, TAG, 'unlockWithPassword failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'unlockWithPassword exception: %{public}s', (e as Error).message);
      setTimeout(() => {
        if (this.mode === 'login' && this.loginBusy) {
          this.loginBusy = false;
          this.loginError = this.tr('网络错误。请检查您的网络连接。');
        }
      }, 8000);
      return;
    }
    if (!done) {
      this.loginBusy = false;
      return;
    }
    this.waitLoginDone(30000);
  }

  // 步骤 2：提交两步验证码，完成登录
  private async submitLoginTotp(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (!this.loginInputValid()) return;
    this.loginBusy = true;
    this.loginError = '';
    let done: boolean = false;
    try {
      const res: BridgeResult = await this.bridge.call('loginTotp', '{"code":' + JSON.stringify(this.loginCode.trim()) + '}');
      if (res.ok) {
        const p: LoginNextPayload = JSON.parse(res.payload) as LoginNextPayload;
        done = this.handleLoginNext(p);
      } else {
        hilog.info(0x0000, TAG, 'loginTotp failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
        this.loginCode = '';
        if (res.error === 'session_expired' || res.error === 'no_login_ctx') {
          // 2FA 会话已失效：SRP 路径回密码步骤重建会话，验证码路径回邮箱步骤
          this.loginStep = this.totpFromSrp ? 1 : 0;
        }
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'loginTotp exception: %{public}s', (e as Error).message);
      // 同 loginPassword：超时后 ext 侧可能仍完成登录，延迟复查避免误报
      setTimeout(() => {
        if (this.mode === 'login' && this.loginBusy) {
          this.loginBusy = false;
          this.loginError = this.tr('网络错误。请检查您的网络连接。');
        }
      }, 8000);
      return;
    }
    if (!done) {
      this.loginBusy = false;
      return;
    }
    this.waitLoginDone(30000);
  }

  // 步骤 3：提交邮箱验证码。登录路径按响应分流；注册路径直接生成注册密钥
  private async submitOtp(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (!this.loginInputValid()) return;
    this.loginBusy = true;
    this.loginError = '';
    let done: boolean = false;
    try {
      const res: BridgeResult = await this.bridge.call('verifyOtt',
        '{"code":' + JSON.stringify(this.loginCode.trim()) + '}');
      if (res.ok) {
        const p: LoginNextPayload = JSON.parse(res.payload) as LoginNextPayload;
        if (this.otpPurpose === 'signup') {
          // 注册：用入口输入的密码直接生成密钥并展示恢复密钥
          await this.runSignupPrepare(this.signupPwd);
        } else {
          done = this.handleLoginNext(p);
        }
      } else {
        hilog.info(0x0000, TAG, 'verifyOtt failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
        this.loginCode = '';
        if (res.error === 'session_expired' || res.error === 'no_login_ctx') {
          this.loginStep = 0;
        }
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'verifyOtt exception: %{public}s', (e as Error).message);
      setTimeout(() => {
        if (this.mode === 'login' && this.loginBusy) {
          this.loginBusy = false;
          this.loginError = this.tr('网络错误。请检查您的网络连接。');
        }
      }, 8000);
      return;
    }
    if (!done) {
      this.loginBusy = false;
      return;
    }
    this.waitLoginDone(30000);
  }

  // 重发邮箱验证码（停留在当前步骤，清空已输入的验证码）
  private async resendOtp(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    this.loginBusy = true;
    this.loginError = '';
    try {
      await this.sendOttAndEnterStep(this.otpPurpose.length > 0 ? this.otpPurpose : 'login');
    } finally {
      this.loginBusy = false;
    }
  }

  // 忘记密码入口：从密码步骤发起应用内恢复（发登录验证码 → 恢复密钥 → 重置密码）。
  // 解锁步骤（OTP 已验证）已在 ext 侧保存 otpAuth，直接进恢复密钥步骤
  private async startPasswordReset(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    this.resettingPassword = true;
    this.recoveryKeyInput = '';
    this.loginError = '';
    if (this.loginPwdUnlock) {
      this.loginStep = 8;
      return;
    }
    this.loginBusy = true;
    try {
      await this.sendOttAndEnterStep('login');
    } finally {
      this.loginBusy = false;
    }
  }

  // 步骤 8：提交恢复密钥（24 词助记词或 64 位十六进制），
  // 用其解密 masterKeyEncryptedWithRecoveryKey 完成登录，进入重置密码步骤
  private async submitRecoveryKey(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (!this.loginInputValid()) return;
    this.loginBusy = true;
    this.loginError = '';
    try {
      const res: BridgeResult = await this.bridge.call('recoverAccount',
        '{"recoveryKey":' + JSON.stringify(this.recoveryKeyInput.trim()) + '}', 180000);
      if (!res.ok) {
        hilog.info(0x0000, TAG, 'recoverAccount failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
        return;
      }
      hilog.info(0x0000, TAG, 'recoverAccount ok, go reset password');
      this.toast(this.tr('恢复成功！'));
      this.setPwd = '';
      this.setPwdConfirm = '';
      this.loginPwdVisible = false;
      this.loginStep = 9;
    } catch (e) {
      hilog.error(0x0000, TAG, 'recoverAccount exception: %{public}s', (e as Error).message);
      this.loginError = this.tr('网络错误。请检查您的网络连接。');
    } finally {
      this.loginBusy = false;
    }
  }

  // 步骤 9：重置新密码（恢复密钥登录成功后，会话已建立）：
  // 复用 changePassword 协议（新随机 kekSalt + Sensitive 阶梯派生新 KEK → /users/srp/update）
  private async submitResetPassword(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (this.setPwd.length < 8) {
      this.loginError = this.tr('密码长度必须至少为 8 个字符。');
      return;
    }
    if (this.pwStrength(this.setPwd) < 0.4) {
      this.loginError = this.tr('请检查您的密码并重试。');
      return;
    }
    if (this.setPwd !== this.setPwdConfirm) {
      this.loginError = this.tr('请确认密码');
      return;
    }
    this.loginBusy = true;
    this.loginError = '';
    let done: boolean = false;
    try {
      const rand: cryptoFramework.DataBlob = cryptoFramework.createRandom().generateRandomSync(16);
      const helper: util.Base64Helper = new util.Base64Helper();
      const kekSaltB64: string = helper.encodeToStringSync(rand.data);
      const ladder: KdfAttempt[] = [
        { ops: 16, mem: 268435456 },
        { ops: 32, mem: 134217728 },
      ];
      let kekB64: string = '';
      let opsUsed: number = 0;
      let memUsed: number = 0;
      for (let i: number = 0; i < ladder.length; i++) {
        const t0: number = Date.now();
        try {
          kekB64 = await this.deriveKekNative(this.setPwd, kekSaltB64, ladder[i].ops, ladder[i].mem);
          opsUsed = ladder[i].ops;
          memUsed = ladder[i].mem;
          hilog.info(0x0000, TAG, 'resetPwd argon2 ok in %{public}dms', Date.now() - t0);
          break;
        } catch (e) {
          hilog.error(0x0000, TAG, 'resetPwd argon2 failed i=%{public}d after %{public}dms: %{public}s',
            i, Date.now() - t0, (e as Error).message);
          kekB64 = '';
        }
      }
      if (kekB64.length === 0) {
        this.loginError = this.loginErrorText('weak_device');
        return;
      }
      const args: string = '{"kekSaltB64":' + JSON.stringify(kekSaltB64)
        + ',"kekB64":' + JSON.stringify(kekB64)
        + ',"opsLimit":' + opsUsed + ',"memLimit":' + memUsed
        + ',"logOutOtherDevices":true}';
      const res: BridgeResult = await this.bridge.call('changePassword', args, 180000);
      if (!res.ok) {
        hilog.error(0x0000, TAG, 'reset changePassword failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
        return;
      }
      hilog.info(0x0000, TAG, 'reset changePassword ok');
      done = true;
      this.toast(this.tr('密码修改成功'));
      // 解除恢复流程标记：pollBridge 恢复取列表，会话就绪后自动进入列表；
      // 保持按钮转圈直到 mode 翻转（waitLoginDone 兜底超时）
      this.resettingPassword = false;
      this.setPwd = '';
      this.setPwdConfirm = '';
      this.waitLoginDone(30000);
    } catch (e) {
      hilog.error(0x0000, TAG, 'reset changePassword exception: %{public}s', (e as Error).message);
      this.loginError = this.tr('网络错误。请检查您的网络连接。');
    } finally {
      if (!done) {
        this.loginBusy = false;
      }
    }
  }

  // 步骤 4：设置密码（登录路径：账户尚未设置密钥，用此密码完成注册）
  private async submitSetPassword(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    if (this.setPwd.length < 8) {
      this.loginError = this.tr('密码长度必须至少为 8 个字符。');
      return;
    }
    if (this.pwStrength(this.setPwd) < 0.4) {
      this.loginError = this.tr('请检查您的密码并重试。');
      return;
    }
    if (this.setPwd !== this.setPwdConfirm) {
      this.loginError = this.tr('请确认密码');
      return;
    }
    this.loginBusy = true;
    this.loginError = '';
    try {
      await this.runSignupPrepare(this.setPwd);
    } finally {
      this.loginBusy = false;
    }
  }

  // 生成注册密钥（kek/masterKey/恢复密钥/SRP 参数），成功后进入恢复密钥展示步骤。
  // kek 由原生 taskpool Argon2id 派生（官方移动端参数阶梯 256MiB/16 → 128MiB/32，
  // 分配失败回退），kekSalt 用系统 RNG 生成；wasm 内不再跑大参数 crypto_pwhash
  private async runSignupPrepare(password: string): Promise<void> {
    if (this.bridge === null) return;
    const backStep: number = this.otpPurpose === 'signup' ? 7 : 4;
    try {
      // 16 字节 kekSalt（等价 libsodium randombytes_buf(crypto_pwhash_SALTBYTES)）
      const rand: cryptoFramework.DataBlob = cryptoFramework.createRandom().generateRandomSync(16);
      const helper: util.Base64Helper = new util.Base64Helper();
      const kekSaltB64: string = helper.encodeToStringSync(rand.data);
      const ladder: KdfAttempt[] = [
        { ops: 16, mem: 268435456 },
        { ops: 32, mem: 134217728 },
      ];
      let kekB64: string = '';
      let opsUsed: number = 0;
      let memUsed: number = 0;
      for (let i: number = 0; i < ladder.length; i++) {
        const t0: number = Date.now();
        try {
          hilog.info(0x0000, TAG, 'native argon2 start ops=%{public}d mem=%{public}d',
            ladder[i].ops, ladder[i].mem);
          kekB64 = await this.deriveKekNative(password, kekSaltB64, ladder[i].ops, ladder[i].mem);
          opsUsed = ladder[i].ops;
          memUsed = ladder[i].mem;
          hilog.info(0x0000, TAG, 'native argon2 ok in %{public}dms', Date.now() - t0);
          break;
        } catch (e) {
          hilog.error(0x0000, TAG, 'native argon2 failed i=%{public}d after %{public}dms: %{public}s',
            i, Date.now() - t0, (e as Error).message);
          kekB64 = '';
        }
      }
      if (kekB64.length === 0) {
        this.loginError = this.loginErrorText('weak_device');
        this.loginStep = backStep;
        return;
      }
      const args: string = '{"kekSaltB64":' + JSON.stringify(kekSaltB64)
        + ',"kekB64":' + JSON.stringify(kekB64)
        + ',"opsLimit":' + opsUsed + ',"memLimit":' + memUsed + '}';
      hilog.info(0x0000, TAG, 'runSignupPrepare start');
      const res: BridgeResult = await this.bridge.call('signupPrepare', args, 600000);
      if (!res.ok) {
        hilog.info(0x0000, TAG, 'signupPrepare failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
        this.loginStep = backStep;
        return;
      }
      const p: SignupPreparePayload = JSON.parse(res.payload) as SignupPreparePayload;
      this.signupMnemonic = p.mnemonic;
      hilog.info(0x0000, TAG, 'signupPrepare ok, mnemonic=%{public}d words, goStep5', p.mnemonic.split(' ').length);
      this.loginStep = 5;
    } catch (e) {
      hilog.error(0x0000, TAG, 'signupPrepare exception: %{public}s', (e as Error).message);
      this.loginError = this.tr('网络错误。请检查您的网络连接。');
      this.loginStep = backStep;
    }
  }

  // 修改密码（对应官方 change_password）：会话已认证，仅需新密码 + 确认。
  // 原生 Argon2id（Sensitive 阶梯）+ 新随机 kekSalt 派生新 KEK → bridge
  // changePassword 完成 secretbox(masterKey,新KEK) 与 /users/srp/update
  private async submitChangePassword(logOutOthers: boolean): Promise<void> {
    if (this.bridge === null || this.cpBusy) return;
    if (this.cpPwd.length < 8) {
      this.cpError = this.tr('密码长度必须至少为 8 个字符。');
      return;
    }
    if (this.pwStrength(this.cpPwd) < 0.4) {
      this.cpError = this.tr('请检查您的密码并重试。');
      return;
    }
    if (this.cpPwd !== this.cpPwdConfirm) {
      this.cpError = this.tr('请确认密码');
      return;
    }
    this.cpBusy = true;
    this.cpError = '';
    try {
      // 16 字节随机 kekSalt（libsodium crypto_pwhash_SALTBYTES 等价）
      const rand: cryptoFramework.DataBlob = cryptoFramework.createRandom().generateRandomSync(16);
      const helper: util.Base64Helper = new util.Base64Helper();
      const kekSaltB64: string = helper.encodeToStringSync(rand.data);
      const ladder: KdfAttempt[] = [
        { ops: 16, mem: 268435456 },
        { ops: 32, mem: 134217728 },
      ];
      let kekB64: string = '';
      let opsUsed: number = 0;
      let memUsed: number = 0;
      for (let i: number = 0; i < ladder.length; i++) {
        const t0: number = Date.now();
        try {
          kekB64 = await this.deriveKekNative(this.cpPwd, kekSaltB64, ladder[i].ops, ladder[i].mem);
          opsUsed = ladder[i].ops;
          memUsed = ladder[i].mem;
          hilog.info(0x0000, TAG, 'changePwd argon2 ok in %{public}dms', Date.now() - t0);
          break;
        } catch (e) {
          hilog.error(0x0000, TAG, 'changePwd argon2 failed i=%{public}d after %{public}dms: %{public}s',
            i, Date.now() - t0, (e as Error).message);
          kekB64 = '';
        }
      }
      if (kekB64.length === 0) {
        this.cpError = this.loginErrorText('weak_device');
        return;
      }
      const args: string = '{"kekSaltB64":' + JSON.stringify(kekSaltB64)
        + ',"kekB64":' + JSON.stringify(kekB64)
        + ',"opsLimit":' + opsUsed + ',"memLimit":' + memUsed
        + ',"logOutOtherDevices":' + (logOutOthers ? 'true' : 'false') + '}';
      const res: BridgeResult = await this.bridge.call('changePassword', args, 180000);
      if (!res.ok) {
        hilog.error(0x0000, TAG, 'changePassword failed: %{public}s', res.error);
        this.cpError = this.loginErrorText(res.error);
        return;
      }
      this.cpPwd = '';
      this.cpPwdConfirm = '';
      this.cpVisible = false;
      this.toast(this.tr('密码修改成功'));
      this.pathStack.pop();
    } catch (e) {
      hilog.error(0x0000, TAG, 'changePassword exception: %{public}s', (e as Error).message);
      this.cpError = this.tr('网络错误。请检查您的网络连接。');
    } finally {
      this.cpBusy = false;
    }
  }

  // 修改密码表单校验（官方阈值：强度 >= 0.4 视为有效，两次输入一致）
  private cpValid(): boolean {
    return this.pwStrength(this.cpPwd) >= 0.4;
  }

  private cpMatch(): boolean {
    return this.cpPwdConfirm.length > 0 && this.cpPwd === this.cpPwdConfirm;
  }

  private cpFormValid(): boolean {
    return this.cpValid() && this.cpMatch();
  }

  // 官方 validFieldValueColor：有效值输入框的淡紫底色（primary700 20% 透明度）
  private cpFieldTint(): string {
    return this.dark ? '#341944' : '#EACFF7';
  }

  // 修改密码提交入口：先校验，再弹"退出其他设备"选择（官方 logOutFromOtherDevices）
  private cpStartChange(): void {
    if (this.cpBusy) return;
    if (this.cpPwd.length < 8) {
      this.cpError = this.tr('密码长度必须至少为 8 个字符。');
      return;
    }
    if (!this.cpValid()) {
      this.cpError = this.tr('请检查您的密码并重试。');
      return;
    }
    if (!this.cpMatch()) {
      this.cpError = this.tr('请确认密码');
      return;
    }
    this.cpError = '';
    this.cpLogOutSheetOpen = true;
  }

  // 步骤 5：确认已保存恢复密钥，完成注册并登录
  private async submitSignupFinish(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    this.loginBusy = true;
    this.loginError = '';
    let done: boolean = false;
    try {
      const res: BridgeResult = await this.bridge.call('signupFinish', '{}', 180000);
      if (res.ok) {
        hilog.info(0x0000, TAG, 'signupFinish ok');
        done = true;
      } else {
        hilog.info(0x0000, TAG, 'signupFinish failed: %{public}s', res.error);
        this.loginError = this.loginErrorText(res.error);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'signupFinish exception: %{public}s', (e as Error).message);
      setTimeout(() => {
        if (this.mode === 'login' && this.loginBusy) {
          this.loginBusy = false;
          this.loginError = this.tr('网络错误。请检查您的网络连接。');
        }
      }, 8000);
      return;
    }
    if (!done) {
      this.loginBusy = false;
      return;
    }
    this.waitLoginDone(30000);
  }

  // 步骤 7（注册入口）：校验后发送注册验证码
  private async submitSignupEntry(): Promise<void> {
    if (this.bridge === null || this.loginBusy) return;
    const email: string = this.loginEmail.trim();
    const at: number = email.indexOf('@');
    if (at < 1 || email.indexOf('.', at) <= at) {
      this.loginError = this.tr('请输入有效的电子邮件地址。');
      return;
    }
    if (this.signupPwd.length < 8) {
      this.loginError = this.tr('密码长度必须至少为 8 个字符。');
      return;
    }
    if (this.pwStrength(this.signupPwd) < 0.4) {
      this.loginError = this.tr('请检查您的密码并重试。');
      return;
    }
    if (this.signupPwd !== this.signupPwdConfirm) {
      this.loginError = this.tr('请确认密码');
      return;
    }
    this.loginEmail = email;
    this.loginBusy = true;
    this.loginError = '';
    try {
      // 注册入口同样先行渲染：等 WebView 引擎就绪再发验证码
      if (!await this.waitWebReady(15000)) {
        this.loginError = this.tr('网络错误。请检查您的网络连接。');
        return;
      }
      await this.sendOttAndEnterStep('signup');
    } finally {
      this.loginBusy = false;
    }
  }

  // 复制恢复密钥助记词
  private async copyRecoveryMnemonic(): Promise<void> {
    try {
      const data: pasteboard.PasteData =
        pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, this.signupMnemonic);
      await pasteboard.getSystemPasteboard().setData(data);
      this.toast(this.tr('恢复密钥已复制到剪贴板'));
    } catch (e) {
      // 剪贴板不可用时忽略
    }
  }

  // 进入通行密钥验证步骤：取验证页地址供复制使用（本机无通行密钥能力，不自动跳浏览器）
  private async enterPasskeyStep(): Promise<void> {
    this.loginStep = 6;
    this.loginError = '';
    this.passkeyUrl = '';
    if (this.bridge === null) return;
    try {
      const res: BridgeResult = await this.bridge.call('passkeyVerifyUrl', '{}');
      if (res.ok) {
        const p: PasskeyVerifyUrlPayload = JSON.parse(res.payload) as PasskeyVerifyUrlPayload;
        this.passkeyUrl = p.url;
        this.passkeyTotpAvailable = p.totpAvailable;
      } else {
        this.loginError = this.loginErrorText(res.error);
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'passkeyVerifyUrl exception: %{public}s', (e as Error).message);
    }
  }

  // 补取通行密钥验证链接（已有缓存时直接返回，不打开浏览器）
  private async refreshPasskeyUrl(): Promise<void> {
    if (this.passkeyUrl.length > 0) return;
    if (this.bridge === null || this.loginBusy) return;
    this.loginBusy = true;
    this.loginError = '';
    try {
      const res: BridgeResult = await this.bridge.call('passkeyVerifyUrl', '{}');
      if (res.ok) {
        const p: PasskeyVerifyUrlPayload = JSON.parse(res.payload) as PasskeyVerifyUrlPayload;
        this.passkeyUrl = p.url;
        this.passkeyTotpAvailable = p.totpAvailable;
      } else {
        this.loginError = this.loginErrorText(res.error);
      }
    } catch (e) {
      this.loginError = this.tr('网络错误。请检查您的网络连接。');
    } finally {
      this.loginBusy = false;
    }
  }

  // 复制通行密钥验证链接：本机无凭证时用户需把链接转移到存有通行密钥的设备
  private async copyPasskeyUrl(): Promise<void> {
    if (this.passkeyUrl.length === 0) return;
    try {
      const data: pasteboard.PasteData =
        pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, this.passkeyUrl);
      await pasteboard.getSystemPasteboard().setData(data);
      this.toast(this.tr('已复制到剪贴板'));
    } catch (e) {
      hilog.error(0x0000, TAG, 'copy passkey url failed: %{public}s', (e as Error).message);
    }
  }

  // 查询通行密钥验证进度。manual=true 时由用户点击触发，仍在等待时 toast 提示
  private async checkPasskeyStatus(manual: boolean): Promise<void> {
    if (this.bridge === null || this.passkeyChecking) return;
    this.passkeyChecking = true;
    try {
      const res: BridgeResult = await this.bridge.call('passkeyStatus', '{}');
      if (res.ok) {
        const p: LoginNextPayload = JSON.parse(res.payload) as LoginNextPayload;
        if (p.verified === false) {
          if (manual) {
            this.toast(this.tr('验证仍在等待中'));
          }
          return;
        }
        this.handleLoginNext(p);
      } else {
        hilog.info(0x0000, TAG, 'passkeyStatus failed: %{public}s', res.error);
        if (res.error === 'session_expired' || res.error === 'no_login_ctx') {
          this.loginError = this.tr('会话已过期');
          this.loginStep = 0;
          return;
        }
        if (manual) {
          this.loginError = this.loginErrorText(res.error);
        }
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'passkeyStatus exception: %{public}s', (e as Error).message);
    } finally {
      this.passkeyChecking = false;
    }
  }

  // 通行密钥验证页改用 TOTP 验证码（ext 侧已保留 twoFactor 会话）
  private switchToTotp(): void {
    if (this.loginBusy) return;
    this.loginCode = '';
    this.loginError = '';
    this.loginStep = 2;
  }

  // 解析服务条款富文本（<u-terms>…</u-terms> / <u-policy>…</u-policy>）为可点片段
  private tosSegments(): TosSegment[] {
    const out: TosSegment[] = [];
    const raw: string = this.tr('我同意 <u-terms>服务条款</u-terms> 和 <u-policy>隐私政策</u-policy>');
    const segs: string[] = raw.split(/(<u-terms>[\s\S]*?<\/u-terms>|<u-policy>[\s\S]*?<\/u-policy>)/);
    for (let i = 0; i < segs.length; i++) {
      const s: string = segs[i];
      if (s.length === 0) {
        continue;
      }
      if (s.indexOf('<u-terms>') === 0) {
        out.push({ text: s.substring(9, s.length - 10), kind: 'terms' });
      } else if (s.indexOf('<u-policy>') === 0) {
        out.push({ text: s.substring(10, s.length - 11), kind: 'policy' });
      } else {
        out.push({ text: s, kind: '' });
      }
    }
    return out;
  }

  // ---------- 网页版登录页（AuthPageShell）复刻：紫品牌带 + 白色圆角底部工作表 ----------

  private loginIsWide(): boolean {
    // 桌面（≥1024vp）与横屏（宽 640–1023 且宽>高）一律左右分栏；
    // 高度用无键盘时的 stableH，键盘弹出不会把内屏横屏翻成上下布局
    return this.rootW >= 1024 || (this.rootW >= 640 && this.rootW > this.stableH);
  }

  private loginIsMid(): boolean {
    return this.rootW >= 640 && this.rootW < 1024;
  }

  // 键盘弹出（RESIZE 避让）后根高不足 500vp 时，手机品牌带压缩为仅 wordmark，
  // 把空间让给表单，保证输入框/按钮在折叠屏外屏等短屏上可达
  private loginHeroCompact(): boolean {
    return this.rootH < 500;
  }

  private loginMobileHeroHeight(): number {
    return (this.loginHeroCompact() ? 64 : 196) + this.topInset;
  }

  // 宽屏卡片无键盘时的稳定高度（vp）：品牌面板固定用它，键盘 RESIZE 压缩窗口时
  // 面板不重排（文案/插画零抖动，超出窗口的部分被裁掉），右侧表单区随窗口压缩、
  // 滚动余量自动增大（按钮滚动可达）
  private loginWidePanelH(): number {
    const top: number = this.rootW >= 1024 ? 40 : Math.max(16, this.topInset);
    const bottom: number = this.rootW >= 1024 ? 40 : Math.max(16, this.safeB);
    const panelH: number = Math.min(780, Math.max(0, this.stableH - top - bottom));
    return panelH;
  }

  // --auth-ui-* 官方色板（浅色严格对齐 web，深色对齐 web dark 变量） --
  private authPageBg(): string {
    return this.dark ? '#0A0A0A' : '#F4F4F4';
  }

  private authCardBg(): string {
    return this.dark ? '#252525' : '#FFFFFF';
  }

  private authText(): string {
    return this.dark ? '#FFFFFF' : '#000000';
  }

  private authMuted(): string {
    return this.dark ? '#999999' : '#666666';
  }

  private authFaint(): string {
    return '#969696';
  }

  private authFieldBg(): string {
    return this.dark ? '#1A1A1A' : '#FFFFFF';
  }

  private authStroke(): string {
    return this.dark ? '#3E3E3E' : '#E0E0E0';
  }

  private authFillHover(): string {
    return this.dark ? '#1A1A1A' : '#DEDEDE';
  }

  private authFillActive(): string {
    return this.dark ? '#292929' : '#D2D2D2';
  }

  private authDisabledText(): string {
    return this.dark ? '#808080' : '#D6D6D6';
  }

  private authLink(): string {
    return this.dark ? '#FFFFFF' : '#000000';
  }

  private authWarn(): string {
    return '#F63A3A';
  }

  private authPrimary(): string {
    return '#9610D6';
  }

  private loginButtonLabel(): string {
    if (this.loginStep === 2 || this.loginStep === 3) {
      return this.tr('验证');
    }
    if (this.loginStep === 4) {
      return this.tr('设置密码');
    }
    if (this.loginStep === 5) {
      return this.tr('继续');
    }
    if (this.loginStep === 6) {
      return this.tr('复制验证链接');
    }
    if (this.loginStep === 7) {
      return this.tr('创建账户');
    }
    if (this.loginStep === 8) {
      return this.tr('恢复');
    }
    if (this.loginStep === 9) {
      return this.tr('重置密码');
    }
    return this.tr('登录');
  }

  // 忙碌时按钮内进度文案：密钥生成相关步骤显示带秒数的提示（按钮高度固定，
  // 内容切换不会挤压下方元素），其余步骤显示通用加载圈
  private loginBusyText(): string {
    if (this.loginStep === 1 || this.loginStep === 3 || this.loginStep === 4
      || this.loginStep === 9) {
      return this.tr('正在生成加密密钥...') + ' ' + this.busySec + 's';
    }
    return '';
  }

  private loginSigninAsText(): string {
    return this.tr('正在以 <a>{{email}}</a> 的身份登录')
      .replace('<a>', '').replace('</a>', '')
      .replace('{{email}}', this.loginEmail);
  }

  private backToEmailStep(): void {
    if (this.loginBusy) {
      return;
    }
    this.loginError = '';
    this.loginPwd = '';
    this.loginCode = '';
    this.loginPwdVisible = false;
    // 中途返回视为放弃恢复流程
    this.resettingPassword = false;
    this.recoveryKeyInput = '';
    // 注册流程返回注册入口，登录流程返回邮箱步骤
    this.loginStep = this.otpPurpose === 'signup' ? 7 : 0;
  }

  private otpAt(i: number): string {
    return i < this.loginCode.length ? this.loginCode.charAt(i) : '';
  }

  private otpFocusCell(i: number): void {
    if (i < 0 || i > 5) {
      return;
    }
    try {
      this.getUIContext().getFocusController().requestFocus('otpCell' + i.toString());
    } catch (e) {
      // 焦点控制不可用时忽略
    }
  }

  // 6 格验证码输入：单格输入自动进格，粘贴整段自动填充，满 6 位自动提交
  private otpChanged(i: number, v: string): void {
    if (this.loginBusy) {
      return;
    }
    if (v.length > 1) {
      let digits: string = '';
      for (let k: number = 0; k < v.length; k++) {
        const ch: string = v.charAt(k);
        if (ch >= '0' && ch <= '9') {
          digits += ch;
        }
      }
      if (digits.length === 0) {
        return;
      }
      this.loginCode = digits.substring(0, 6);
      this.loginError = '';
      if (this.loginCode.length >= 6) {
        this.otpFocusCell(5);
        this.submitLoginStep();
      } else {
        this.otpFocusCell(this.loginCode.length);
      }
      return;
    }
    if (v.length === 1) {
      const cur: string = this.loginCode;
      const next: string = i >= cur.length ? cur + v : cur.substring(0, i) + v + cur.substring(i + 1);
      this.loginCode = next;
      this.loginError = '';
      if (next.length >= 6) {
        this.otpFocusCell(Math.min(i + 1, 5));
        this.submitLoginStep();
      } else {
        this.otpFocusCell(i + 1);
      }
      return;
    }
    // 删除：清掉当前格并回焦上一格
    const curDel: string = this.loginCode;
    if (i < curDel.length) {
      this.loginCode = curDel.substring(0, i) + curDel.substring(i + 1);
    }
    this.otpFocusCell(i - 1);
  }

  @Builder
  loginBrandBullet(label: string) {
    Row({ space: 12 }) {
      Column() {
        SymbolGlyph($r('sys.symbol.checkmark'))
          .fontSize(12)
          .fontColor(['#FFFFFF'])
      }
      .width(24)
      .height(24)
      .borderRadius(12)
      .backgroundColor('#24FFFFFF')
      .justifyContent(FlexAlign.Center)
      .alignItems(HorizontalAlign.Center)
      Text(label)
        .fontSize(17)
        .lineHeight(24)
        .fontWeight(FontWeight.Medium)
        .fontColor('#FFFFFF')
    }
    .alignItems(VerticalAlign.Center)
  }

  // 品牌带：紫底 + 曲线纹理 + Ente 字标 + 文案 + 鸭子插画（对齐官方 BrandPanel）
  @Builder
  loginBrandPanel(size: string) {
    Stack({ alignContent: Alignment.TopStart }) {
      Column()
        .width('100%')
        .height('100%')
        .backgroundColor(this.authPrimary())
      Image($rawfile('web/images/auth-frame-curves.svg'))
        .objectFit(ImageFit.Cover)
        .width('100%')
        .height('100%')
        .opacity(this.dark ? 0.08 : 0.3)
        .hitTestBehavior(HitTestMode.None)
      if (size === 'desktop') {
        Column() {
          Image($rawfile('brand/ente-wordmark.svg'))
            .width(this.rootW >= 1024 ? 83 : 64)
            .height(this.rootW >= 1024 ? 26 : 20)
            .objectFit(ImageFit.Fill)
          if (this.stableH >= 300) {
            Column() {
              Text(this.tr('您双重认证验证码的安全之家'))
                .fontSize(this.rootW >= 1024 ? 42 : 28)
                .lineHeight(this.rootW >= 1024 ? 50 : 36)
                .fontWeight(600)
                .fontColor('#FFFFFF')
                .fontFamily('Outfit')
                .letterSpacing(this.rootW >= 1024 ? -0.8 : -0.5)
                .constraintSize({ maxWidth: this.rootW >= 1024 ? 300 : 260 })
                .maxLines(2)
              Text(this.tr('端到端加密。跨平台。开源。'))
                .fontSize(this.rootW >= 1024 ? 20 : 15)
                .lineHeight(this.rootW >= 1024 ? 28 : 22)
                .fontWeight(FontWeight.Medium)
                .fontColor('#E0FFFFFF')
                .margin({ top: this.rootW >= 1024 ? 16 : 12 })
              if (this.stableH > (this.rootW >= 1024 ? 400 : 520)) {
                Column({ space: 12 }) {
                  this.loginBrandBullet(this.tr('永久免费'))
                  this.loginBrandBullet(this.tr('无广告，无窥探'))
                  this.loginBrandBullet(this.tr('通过独立审计'))
                }
                .margin({ top: 24 })
                .alignItems(HorizontalAlign.Start)
              }
            }
            .margin({ top: 32 })
            .alignItems(HorizontalAlign.Start)
          }
          if (this.rootW >= 1024 || this.stableH >= 360) {
            Blank()
            Image($rawfile('web/images/auth-ducky.svg'))
              .width(this.rootW >= 1024 ? 313 : (this.stableH >= 500 ? 200 : 144))
              .height(this.rootW >= 1024 ? 245 : (this.stableH >= 500 ? 156 : 112))
              .objectFit(ImageFit.Contain)
              .alignSelf(ItemAlign.Center)
          }
        }
        .padding(this.rootW >= 1024 ? 44 : 32)
        .width('100%')
        .height('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (size === 'tablet') {
        Column() {
          Image($rawfile('brand/ente-wordmark.svg'))
            .width(77)
            .height(24)
            .objectFit(ImageFit.Fill)
          Text(this.tr('您双重认证验证码的安全之家'))
            .fontSize(34)
            .lineHeight(42)
            .fontWeight(600)
            .fontColor('#FFFFFF')
            .fontFamily('Outfit')
            .letterSpacing(-0.7)
            .constraintSize({ maxWidth: 380 })
            .maxLines(2)
            .margin({ top: 24 })
          Text(this.tr('端到端加密。跨平台。开源。'))
            .fontSize(17)
            .lineHeight(24)
            .fontWeight(FontWeight.Medium)
            .fontColor('#E0FFFFFF')
            .margin({ top: 10 })
        }
        .padding({ left: 40, right: 40, top: 40, bottom: 60 })
        .width('100%')
        .height('100%')
        .alignItems(HorizontalAlign.Start)
      } else {
        Column() {
          Image($rawfile('brand/ente-wordmark.svg'))
            .width(64)
            .height(20)
            .objectFit(ImageFit.Fill)
            .margin({ left: 8, top: 8 })
          if (!this.loginHeroCompact()) {
            Text(this.tr('您双重认证验证码的安全之家'))
              .fontSize(26)
              .lineHeight(34)
              .fontWeight(600)
              .fontColor('#FFFFFF')
              .fontFamily('Outfit')
              .letterSpacing(-0.5)
              .constraintSize({ maxWidth: 188 })
              .maxLines(2)
              .margin({ left: 8 })
          }
        }
        .padding({ left: 16, right: 16, top: 18 + this.topInset, bottom: 40 })
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        .alignItems(HorizontalAlign.Start)
      }
      if (size !== 'desktop' && !(size === 'mobile' && this.loginHeroCompact())) {
        Row() {
          Blank()
          Image($rawfile('web/images/auth-ducky.svg'))
            .width(size === 'tablet' ? 237 : 175)
            .height(size === 'tablet' ? 185 : 137)
            .objectFit(ImageFit.Contain)
            .margin({ right: size === 'tablet' ? 28 : -4, bottom: size === 'tablet' ? 44 : 38 })
        }
        .width('100%')
        .height('100%')
        .alignItems(VerticalAlign.Bottom)
        .hitTestBehavior(HitTestMode.None)
      }
    }
    .width(size === 'desktop'
      ? (this.rootW >= 1024 ? 440 : Math.min(440, Math.max(280, this.rootW - 480)))
      : '100%')
    .height(size === 'mobile' ? this.loginMobileHeroHeight() : (size === 'tablet' ? 268 : (this.stableH > 0 ? this.loginWidePanelH() : '100%')))
    .clip(true)
  }

  // 白色圆角底部工作表：上移 28/32px 与品牌带重叠（对齐官方 ContentSheet）
  @Builder
  loginOverlaySheet(size: string) {
    Column() {
      Column() {
        if (size === 'tablet') {
          Column()
            .width(36)
            .height(4)
            .borderRadius(2)
            .backgroundColor(this.authFillActive())
        }
        Scroll() {
          this.loginForm()
        }
        .scrollBar(BarState.Off)
        .align(size === 'tablet' ? Alignment.Center : Alignment.Top)
        .width('100%')
        .layoutWeight(1)
        .margin({ top: size === 'tablet' ? 20 : 0 })
      }
      .width('100%')
      .layoutWeight(1)
      .borderRadius({ topLeft: 24, topRight: 24 })
      .backgroundColor(this.authCardBg())
      .clip(true)
      .padding(size === 'tablet'
        ? { top: 16, left: 48, right: 48, bottom: 48 }
        : { top: 40, left: 24, right: 24, bottom: Math.max(32, this.safeB + 16) })
    }
    .width('100%')
    .height('100%')
    .padding({ top: size === 'tablet' ? 236 : this.loginMobileHeroHeight() - 28 })
  }

  // 桌面（≥1024vp）/ 手机横屏右侧表单列（对齐官方 ContentSheet 桌面分支）
  @Builder
  loginDesktopContent() {
    Column() {
      Scroll() {
        this.loginForm()
      }
      .scrollBar(BarState.Off)
      .align(Alignment.Center)
      .width('100%')
      .layoutWeight(1)
    }
    .width('100%')
    .layoutWeight(1)
    .height('100%')
    .padding(this.rootW >= 1024
      ? { top: 48, bottom: 48, left: 96, right: 96 }
      : { top: 24, bottom: 24, left: 40, right: 40 })
  }

  @Builder
  loginHeader(title: string, subtitle: string) {
    Column({ space: 8 }) {
      Text(title)
        .fontSize(this.loginIsWide() || this.loginIsMid() ? 30 : 26)
        .lineHeight(this.loginIsWide() || this.loginIsMid() ? 38 : 34)
        .fontWeight(600)
        .fontColor(this.authText())
        .fontFamily('Outfit')
      Text(subtitle)
        .fontSize(this.loginIsWide() || this.loginIsMid() ? 16 : 13)
        .lineHeight(this.loginIsWide() || this.loginIsMid() ? 24 : 20)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  @Builder
  loginEmailField() {
    Column({ space: 9 }) {
      Text(this.tr('电子邮件地址'))
        .fontSize(12)
        .lineHeight(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
      Stack() {
        TextInput({ text: this.loginEmail, placeholder: 'name@example.com' })
          .type(InputType.Email)
          .height(52)
          .width('100%')
          .padding({ left: 16, right: 16 })
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
          .placeholderColor(this.authFaint())
          .placeholderFont({ size: 14, weight: FontWeight.Medium })
          .backgroundColor(Color.Transparent)
          .caretColor(this.authPrimary())
          .enterKeyType(EnterKeyType.Done)
          .defaultFocus(true)
          .enabled(!this.loginBusy)
          .onFocus(() => {
            this.loginFocus = 'email';
          })
          .onBlur(() => {
            if (this.loginFocus === 'email') {
              this.loginFocus = '';
            }
          })
          .onChange((v: string) => {
            this.loginEmail = v;
            this.loginError = '';
          })
          .onSubmit(() => {
            if (this.loginStep === 7) {
              this.submitSignupEntry();
            } else {
              this.submitLoginEmail();
            }
          })
      }
      .width('100%')
      .height(52)
      .borderRadius(16)
      .backgroundColor(this.authFieldBg())
      .border({
        width: 1,
        color: this.loginError.length > 0 ? this.authWarn()
          : (this.loginFocus === 'email' ? this.authPrimary() : this.authStroke()),
      })
      if (this.loginError.length > 0) {
        Text(this.loginError)
          .fontSize(12)
          .lineHeight(16)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authWarn())
          .width('100%')
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  @Builder
  loginPasswordField() {
    Column({ space: 9 }) {
      Text(this.tr('密码'))
        .fontSize(12)
        .lineHeight(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
      Stack({ alignContent: Alignment.End }) {
        TextInput({ text: this.loginPwd })
          .type(this.loginPwdVisible ? InputType.Normal : InputType.Password)
          .showPasswordIcon(false)
          .height(52)
          .width('100%')
          .padding({ left: 16, right: 48 })
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
          .backgroundColor(Color.Transparent)
          .caretColor(this.authPrimary())
          .enterKeyType(EnterKeyType.Done)
          .defaultFocus(true)
          .enabled(!this.loginBusy)
          .onFocus(() => {
            this.loginFocus = 'pwd';
          })
          .onBlur(() => {
            if (this.loginFocus === 'pwd') {
              this.loginFocus = '';
            }
          })
          .onChange((v: string) => {
            this.loginPwd = v;
            this.loginError = '';
          })
          .onSubmit(() => {
            if (this.loginPwdUnlock) {
              this.submitLoginUnlock();
            } else {
              this.submitLoginPassword();
            }
          })
        Button({ type: ButtonType.Normal, stateEffect: false }) {
          SymbolGlyph(this.loginPwdVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
            .fontSize(20)
            .fontColor([this.authFaint()])
        }
        .width(28)
        .height(28)
        .margin({ right: 12 })
        .padding(0)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.loginPwdVisible = !this.loginPwdVisible;
        })
      }
      .width('100%')
      .height(52)
      .borderRadius(16)
      .backgroundColor(this.authFieldBg())
      .border({
        width: 1,
        color: this.loginError.length > 0 ? this.authWarn()
          : (this.loginFocus === 'pwd' ? this.authPrimary() : this.authStroke()),
      })
      if (this.loginError.length > 0) {
        Text(this.loginError)
          .fontSize(12)
          .lineHeight(16)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authWarn())
          .width('100%')
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  @Builder
  loginOtpField() {
    Column({ space: 16 }) {
      Row({ space: 8 }) {
        ForEach([0, 1, 2, 3, 4, 5], (idx: number) => {
          Stack() {
            TextInput({ text: this.otpAt(idx) })
              .id('otpCell' + idx.toString())
              .type(InputType.Number)
              .maxLength(idx === 0 ? 6 : 1)
              .width('100%')
              .height('100%')
              .padding(0)
              .fontSize(24)
              .fontWeight(600)
              .fontFamily('Outfit')
              .textAlign(TextAlign.Center)
              .fontColor(this.authText())
              .backgroundColor(Color.Transparent)
              .caretColor(this.authPrimary())
              .enterKeyType(EnterKeyType.Done)
              .enabled(!this.loginBusy)
              .defaultFocus(idx === 0)
              .onFocus(() => {
                this.otpFocusIdx = idx;
              })
              .onBlur(() => {
                if (this.otpFocusIdx === idx) {
                  this.otpFocusIdx = -1;
                }
              })
              .onChange((v: string) => {
                this.otpChanged(idx, v);
              })
              .onSubmit(() => {
                this.submitLoginStep();
              })
          }
          .layoutWeight(1)
          .aspectRatio(44 / 52)
          .borderRadius(16)
          .backgroundColor(this.authFieldBg())
          .border({
            width: 1,
            color: this.loginError.length > 0 ? this.authWarn()
              : (this.otpFocusIdx === idx ? this.authPrimary() : this.authStroke()),
          })
        }, (idx: number) => idx.toString())
      }
      .width('100%')
      if (this.loginError.length > 0) {
        Text(this.loginError)
          .fontSize(12)
          .lineHeight(16)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authWarn())
          .width('100%')
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  // 注册入口：服务条款勾选行（解析 <u-terms>/<u-policy> 富文本为可点片段）
  @Builder
  loginTosRow() {
    Row({ space: 8 }) {
      Checkbox()
        .select(this.tosAccepted)
        .selectedColor(this.authPrimary())
        .width(16)
        .height(16)
        .onChange((v: boolean) => {
          this.tosAccepted = v;
        })
      Flex({ wrap: FlexWrap.Wrap }) {
        ForEach(this.tosSegments(), (seg: TosSegment) => {
          if (seg.kind === 'terms' || seg.kind === 'policy') {
            Text(seg.text)
              .fontSize(12)
              .lineHeight(18)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.authLink())
              .decoration({ type: TextDecorationType.Underline })
              .onClick(() => {
                this.openUrl(seg.kind === 'terms'
                  ? 'https://ente.com/terms' : 'https://ente.com/privacy');
              })
          } else {
            Text(seg.text)
              .fontSize(12)
              .lineHeight(18)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.authMuted())
          }
        }, (seg: TosSegment, idx: number) => idx.toString() + ':' + seg.text)
      }
      .layoutWeight(1)
    }
    .width('100%')
    .alignItems(VerticalAlign.Top)
  }

  // 注册入口：密码输入（含强度提示）
  @Builder
  signupPasswordField() {
    Column({ space: 9 }) {
      Text(this.tr('密码'))
        .fontSize(12)
        .lineHeight(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
      Stack({ alignContent: Alignment.End }) {
        TextInput({ text: this.signupPwd })
          .type(this.loginPwdVisible ? InputType.Normal : InputType.Password)
          .showPasswordIcon(false)
          .height(52)
          .width('100%')
          .padding({ left: 16, right: 48 })
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
          .backgroundColor(Color.Transparent)
          .caretColor(this.authPrimary())
          .enterKeyType(EnterKeyType.Done)
          .enabled(!this.loginBusy)
          .onChange((v: string) => {
            this.signupPwd = v;
            this.loginError = '';
          })
          .onSubmit(() => {
            this.submitSignupEntry();
          })
        Button({ type: ButtonType.Normal, stateEffect: false }) {
          SymbolGlyph(this.loginPwdVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
            .fontSize(20)
            .fontColor([this.authFaint()])
        }
        .width(28)
        .height(28)
        .margin({ right: 12 })
        .padding(0)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.loginPwdVisible = !this.loginPwdVisible;
        })
      }
      .width('100%')
      .height(52)
      .borderRadius(16)
      .backgroundColor(this.authFieldBg())
      .border({
        width: 1,
        color: this.loginError.length > 0 ? this.authWarn() : this.authStroke(),
      })
      if (this.signupPwd.length > 0) {
        Text(this.pwStrengthText(this.signupPwd))
          .fontSize(12)
          .lineHeight(16)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.pwStrengthColor(this.pwStrength(this.signupPwd)))
          .width('100%')
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  // 注册入口：确认密码输入
  @Builder
  signupPasswordConfirmField() {
    Column({ space: 9 }) {
      Text(this.tr('再次输入密码'))
        .fontSize(12)
        .lineHeight(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
      Stack({ alignContent: Alignment.End }) {
        TextInput({ text: this.signupPwdConfirm })
          .type(this.loginPwdVisible ? InputType.Normal : InputType.Password)
          .showPasswordIcon(false)
          .height(52)
          .width('100%')
          .padding({ left: 16, right: 48 })
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
          .backgroundColor(Color.Transparent)
          .caretColor(this.authPrimary())
          .enterKeyType(EnterKeyType.Done)
          .enabled(!this.loginBusy)
          .onChange((v: string) => {
            this.signupPwdConfirm = v;
            this.loginError = '';
          })
          .onSubmit(() => {
            this.submitSignupEntry();
          })
        Button({ type: ButtonType.Normal, stateEffect: false }) {
          SymbolGlyph(this.loginPwdVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
            .fontSize(20)
            .fontColor([this.authFaint()])
        }
        .width(28)
        .height(28)
        .margin({ right: 12 })
        .padding(0)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.loginPwdVisible = !this.loginPwdVisible;
        })
      }
      .width('100%')
      .height(52)
      .borderRadius(16)
      .backgroundColor(this.authFieldBg())
      .border({
        width: 1,
        color: this.loginError.length > 0 ? this.authWarn() : this.authStroke(),
      })
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  // 步骤 4：设置密码输入（含强度提示）
  @Builder
  setPasswordField() {
    Column({ space: 9 }) {
      Text(this.tr('密码'))
        .fontSize(12)
        .lineHeight(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
      Stack({ alignContent: Alignment.End }) {
        TextInput({ text: this.setPwd })
          .type(this.loginPwdVisible ? InputType.Normal : InputType.Password)
          .showPasswordIcon(false)
          .height(52)
          .width('100%')
          .padding({ left: 16, right: 48 })
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
          .backgroundColor(Color.Transparent)
          .caretColor(this.authPrimary())
          .enterKeyType(EnterKeyType.Done)
          .enabled(!this.loginBusy)
          .onChange((v: string) => {
            this.setPwd = v;
            this.loginError = '';
          })
          .onSubmit(() => {
            // 步骤 4 设密码 / 步骤 9 重置密码共用，按当前步骤分发
            this.submitLoginStep();
          })
        Button({ type: ButtonType.Normal, stateEffect: false }) {
          SymbolGlyph(this.loginPwdVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
            .fontSize(20)
            .fontColor([this.authFaint()])
        }
        .width(28)
        .height(28)
        .margin({ right: 12 })
        .padding(0)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.loginPwdVisible = !this.loginPwdVisible;
        })
      }
      .width('100%')
      .height(52)
      .borderRadius(16)
      .backgroundColor(this.authFieldBg())
      .border({
        width: 1,
        color: this.loginError.length > 0 ? this.authWarn() : this.authStroke(),
      })
      if (this.setPwd.length > 0) {
        Text(this.pwStrengthText(this.setPwd))
          .fontSize(12)
          .lineHeight(16)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.pwStrengthColor(this.pwStrength(this.setPwd)))
          .width('100%')
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  // 步骤 4：确认密码输入
  @Builder
  setPasswordConfirmField() {
    Column({ space: 9 }) {
      Text(this.tr('再次输入密码'))
        .fontSize(12)
        .lineHeight(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authMuted())
      Stack({ alignContent: Alignment.End }) {
        TextInput({ text: this.setPwdConfirm })
          .type(this.loginPwdVisible ? InputType.Normal : InputType.Password)
          .showPasswordIcon(false)
          .height(52)
          .width('100%')
          .padding({ left: 16, right: 48 })
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
          .backgroundColor(Color.Transparent)
          .caretColor(this.authPrimary())
          .enterKeyType(EnterKeyType.Done)
          .enabled(!this.loginBusy)
          .onChange((v: string) => {
            this.setPwdConfirm = v;
            this.loginError = '';
          })
          .onSubmit(() => {
            // 步骤 4 设密码 / 步骤 9 重置密码共用，按当前步骤分发
            this.submitLoginStep();
          })
        Button({ type: ButtonType.Normal, stateEffect: false }) {
          SymbolGlyph(this.loginPwdVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
            .fontSize(20)
            .fontColor([this.authFaint()])
        }
        .width(28)
        .height(28)
        .margin({ right: 12 })
        .padding(0)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.loginPwdVisible = !this.loginPwdVisible;
        })
      }
      .width('100%')
      .height(52)
      .borderRadius(16)
      .backgroundColor(this.authFieldBg())
      .border({
        width: 1,
        color: this.loginError.length > 0 ? this.authWarn() : this.authStroke(),
      })
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  // 步骤 5：恢复密钥展示（助记词 + 复制按钮）
  @Builder
  recoveryKeyBox() {
    Column({ space: 12 }) {
      Text(this.signupMnemonic)
        .fontSize(15)
        .lineHeight(24)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.authText())
        .width('100%')
        .padding(16)
        .borderRadius(16)
        .backgroundColor(this.authFieldBg())
        .border({ width: 1, color: this.authStroke() })
        .copyOption(CopyOptions.LocalDevice)
      Row() {
        Blank()
        Button({ type: ButtonType.Normal, stateEffect: false }) {
          SymbolGlyph($r('sys.symbol.rectangle_on_rectangle'))
            .fontSize(20)
            .fontColor([this.authLink()])
        }
        .width(32)
        .height(32)
        .padding(0)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.copyRecoveryMnemonic();
        })
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  // 步骤 6：手动检查通行密钥验证进度
  @Builder
  passkeyCheckButton() {
    Button() {
      if (this.passkeyChecking) {
        LoadingProgress()
          .width(20)
          .height(20)
          .color(this.authMuted())
      } else {
        Text(this.tr('检查状态'))
          .fontSize(14)
          .lineHeight(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.authText())
      }
    }
    .height(52)
    .width('100%')
    .borderRadius(20)
    .backgroundColor(Color.Transparent)
    .border({ width: 1, color: this.authStroke() })
    .enabled(!this.passkeyChecking)
    .onClick(() => {
      this.checkPasskeyStatus(true);
    })
  }

  @Builder
  loginPrimaryButton() {
    Button() {
      if (this.loginBusy) {
        if (this.loginBusyText().length > 0) {
          Text(this.loginBusyText())
            .fontSize(14)
            .lineHeight(20)
            .fontWeight(FontWeight.Medium)
            .fontColor('#FFFFFF')
        } else {
          LoadingProgress()
            .width(20)
            .height(20)
            .color('#FFFFFF')
        }
      } else {
        Text(this.loginButtonLabel())
          .fontSize(14)
          .lineHeight(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.loginStep > 0 && !this.loginInputValid() ? this.authDisabledText() : '#FFFFFF')
      }
    }
    .height(52)
    .width('100%')
    .borderRadius(20)
    .backgroundColor(this.loginStep > 0 && !this.loginInputValid() ? this.authFillHover() : this.authPrimary())
    .enabled(!this.loginBusy && (this.loginStep === 0 || this.loginInputValid()))
    .onClick(() => {
      this.submitLoginStep();
    })
  }

  @Builder
  loginForm() {
    Column({ space: 24 }) {
      if (this.loginStep === 0) {
        this.loginHeader(this.tr('欢迎回来'), this.tr('输入您的信息以继续。'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.loginEmailField()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 16 }) {
            this.loginPrimaryButton()
            Column({ space: 10 }) {
              Row({ space: 6 }) {
                Text(this.tr('还没有账户？'))
                  .fontSize(14)
                  .lineHeight(20)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(this.authMuted())
                Text(this.tr('注册'))
                  .fontSize(14)
                  .lineHeight(20)
                  .fontWeight(600)
                  .fontColor(this.authLink())
                  .onClick(() => {
                    if (this.loginBusy) {
                      return;
                    }
                    this.otpPurpose = '';
                    this.loginError = '';
                    this.loginStep = 7;
                  })
              }
              .alignItems(VerticalAlign.Center)
            }
            .alignItems(HorizontalAlign.Center)
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 1) {
        this.loginHeader(this.tr('输入您的密码'), this.loginSigninAsText())
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.loginPasswordField()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 12 }) {
            this.loginPrimaryButton()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
        Row() {
          Text(this.tr('忘记密码'))
            .fontSize(14)
            .lineHeight(20)
            .fontWeight(600)
            .fontColor(this.authLink())
            .onClick(() => {
              if (this.loginBusy) {
                return;
              }
              // 应用内恢复流程（官方 recover account）：OTP → 恢复密钥 → 重置密码
              this.startPasswordReset();
            })
          Blank()
          Text(this.tr('更改电子邮件'))
            .fontSize(14)
            .lineHeight(20)
            .fontWeight(600)
            .fontColor(this.authLink())
            .onClick(() => {
              this.backToEmailStep();
            })
        }
        .width('100%')
        .alignItems(VerticalAlign.Center)
      } else if (this.loginStep === 2) {
        this.loginHeader(this.tr('双重认证'), this.tr('请输入您从身份验证器应用中获取的 6 位数字代码。'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.loginOtpField()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 16 }) {
            this.loginPrimaryButton()
            Row() {
              Text(this.tr('丢失了双重认证设备'))
                .fontSize(14)
                .lineHeight(20)
                .fontWeight(600)
                .fontColor(this.authLink())
                .onClick(() => {
                  if (this.loginBusy) {
                    return;
                  }
                  this.openUrl('https://auth.ente.com/two-factor/recover');
                })
              Blank()
              Text(this.tr('更改电子邮件'))
                .fontSize(14)
                .lineHeight(20)
                .fontWeight(600)
                .fontColor(this.authLink())
                .onClick(() => {
                  this.backToEmailStep();
                })
            }
            .width('100%')
            .alignItems(VerticalAlign.Center)
          }
          .width('100%')
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 3) {
        this.loginHeader(this.tr('验证'),
          this.tr('@weHaveSentCode').replace('{email}', this.loginEmail))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.loginOtpField()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 16 }) {
            Column({ space: 12 }) {
              this.loginPrimaryButton()
            }
            .width('100%')
            .alignItems(HorizontalAlign.Center)
            Row() {
              Text(this.tr('重新发送验证码'))
                .fontSize(14)
                .lineHeight(20)
                .fontWeight(600)
                .fontColor(this.authLink())
                .onClick(() => {
                  this.resendOtp();
                })
              Blank()
              Text(this.tr('更改电子邮件'))
                .fontSize(14)
                .lineHeight(20)
                .fontWeight(600)
                .fontColor(this.authLink())
                .onClick(() => {
                  this.backToEmailStep();
                })
            }
            .width('100%')
            .alignItems(VerticalAlign.Center)
          }
          .width('100%')
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 4) {
        this.loginHeader(this.tr('设置密码'), this.tr('输入我们可以用来加密您的数据的新密码'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.setPasswordField()
            this.setPasswordConfirmField()
            Text(this.tr('我们不存储此密码，因此如果您忘记了它，<underline>我们将无法解密您的数据</underline>')
              .replace('<underline>', '').replace('</underline>', ''))
              .fontSize(12)
              .lineHeight(18)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.authWarn())
              .width('100%')
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 12 }) {
            this.loginPrimaryButton()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 5) {
        this.loginHeader(this.tr('恢复密钥'),
          this.tr('我们不会存储此密钥，请将这 24 个单词的密钥保存在安全的地方。'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.recoveryKeyBox()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 16 }) {
            this.loginPrimaryButton()
          }
          .width('100%')
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 6) {
        Row({ space: 2 }) {
          SymbolGlyph($r('sys.symbol.chevron_left'))
            .fontSize(20)
            .fontColor([this.authLink()])
          Text(this.tr('返回'))
            .fontSize(14)
            .lineHeight(20)
            .fontWeight(600)
            .fontColor(this.authLink())
        }
        .alignItems(VerticalAlign.Center)
        .onClick(() => {
          if (this.loginBusy) {
            return;
          }
          this.backToEmailStep();
        })
        this.loginHeader(this.tr('通行密钥验证'), this.tr('等待验证...'))
        Column({ space: 24 }) {
          Text(this.tr('鸿蒙系统暂未支持通行密钥所需的 WebAuthn 标准，本机无法直接完成验证。请复制验证链接，在存有通行密钥的设备（例如电脑）上打开并完成验证；验证完成后返回此应用，我们会自动确认。'))
            .fontSize(14)
            .lineHeight(20)
            .fontColor(this.authMuted())
          Column({ space: 16 }) {
            this.passkeyCheckButton()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 16 }) {
            this.loginPrimaryButton()
            Column({ space: 10 }) {
              if (this.passkeyTotpAvailable) {
                Text(this.tr('使用 TOTP 登录'))
                  .fontSize(14)
                  .lineHeight(20)
                  .fontWeight(600)
                  .fontColor(this.authLink())
                  .onClick(() => {
                    this.switchToTotp();
                  })
              }
              Text(this.tr('恢复账户'))
                .fontSize(14)
                .lineHeight(20)
                .fontWeight(600)
                .fontColor(this.authLink())
                .onClick(() => {
                  this.openUrl('https://auth.ente.com/recover');
                })
            }
            .alignItems(HorizontalAlign.Center)
          }
          .width('100%')
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 8) {
        // 步骤 8：恢复密钥（官方 RecoveryPage：recover_account / auth_recover_account_subtitle）
        this.loginHeader(this.tr('恢复账户'),
          this.tr('请输入您创建账户时保存的恢复密钥。'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
          Stack() {
            TextArea({ text: this.recoveryKeyInput, placeholder: this.tr('输入您的恢复密钥') })
              .height('100%')
              .width('100%')
              .padding(14)
              .fontSize(14)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.authText())
              .backgroundColor(Color.Transparent)
              .caretColor(this.authPrimary())
              .enabled(!this.loginBusy)
              .onChange((v: string) => {
                this.recoveryKeyInput = v;
                this.loginError = '';
              })
          }
          .height(120)
          .width('100%')
          .borderRadius(16)
          .backgroundColor(this.authFieldBg())
          .border({
            width: 1,
            color: this.loginError.length > 0 ? this.authWarn() : this.authStroke(),
          })
            Text(this.tr('没有恢复密钥吗？'))
              .fontSize(13)
              .lineHeight(18)
              .fontWeight(600)
              .fontColor(this.authPrimary())
              .decoration({ type: TextDecorationType.Underline })
              .width('100%')
              .textAlign(TextAlign.End)
              .onClick(() => {
                AlertDialog.show({
                  title: this.tr('没有恢复密钥吗？'),
                  message: this.tr('由于我们端到端加密协议的性质，如果没有您的密码或恢复密钥，您的数据将无法解密'),
                  primaryButton: {
                    value: this.tr('联系支持'),
                    action: () => {
                      this.openUrl('https://ente.io/support');
                    },
                  },
                  secondaryButton: {
                    value: this.tr('取消'),
                    action: () => {
                    },
                  },
                });
              })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 12 }) {
            this.loginPrimaryButton()
            Text(this.tr('更改电子邮件'))
              .fontSize(14)
              .lineHeight(20)
              .fontWeight(600)
              .fontColor(this.authLink())
              .onClick(() => {
                this.backToEmailStep();
              })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else if (this.loginStep === 9) {
        // 步骤 9：重置新密码（官方 PasswordEntryPage reset 模式，无返回）
        this.loginHeader(this.tr('重置密码'),
          this.tr('输入我们可以用来加密您的数据的新密码'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.setPasswordField()
            this.setPasswordConfirmField()
            Text(this.tr('我们不存储此密码，因此如果您忘记了它，<underline>我们将无法解密您的数据</underline>')
              .replace('<underline>', '').replace('</underline>', ''))
              .fontSize(12)
              .lineHeight(18)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.authMuted())
              .width('100%')
            Text(this.tr('工作原理') + '?')
              .fontSize(13)
              .lineHeight(18)
              .fontWeight(600)
              .fontColor(this.authPrimary())
              .decoration({ type: TextDecorationType.Underline })
              .width('100%')
              .textAlign(TextAlign.End)
              .onClick(() => {
                this.openUrl('https://ente.com/architecture');
              })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 12 }) {
            this.loginPrimaryButton()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      } else {
        // 步骤 7：注册入口
        Row({ space: 2 }) {
          SymbolGlyph($r('sys.symbol.chevron_left'))
            .fontSize(20)
            .fontColor([this.authLink()])
          Text(this.tr('返回'))
            .fontSize(14)
            .lineHeight(20)
            .fontWeight(600)
            .fontColor(this.authLink())
        }
        .alignItems(VerticalAlign.Center)
        .onClick(() => {
          if (this.loginBusy) {
            return;
          }
          this.otpPurpose = '';
          this.loginError = '';
          this.loginStep = 0;
        })
        this.loginHeader(this.tr('创建账户'), this.tr('输入您的信息以继续。'))
        Column({ space: 24 }) {
          Column({ space: 16 }) {
            this.loginEmailField()
            this.signupPasswordField()
            this.signupPasswordConfirmField()
            this.loginTosRow()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          Column({ space: 16 }) {
            this.loginPrimaryButton()
          }
          .width('100%')
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      }
    }
    .width(this.loginIsWide() && this.rootW >= 1024 ? 400 : '100%')
    // 注意：不要在这里加 constraintSize({ minHeight: '100%' })——Scroll 内部的百分比 minHeight
    // 会让 ArkUI 的可滚动范围计算失效（内容明明超出视口也滚不动，折叠屏外屏键盘态按钮不可达）
  }

  // 原生分步登录层：完全复刻网页版登录页（AuthPageShell），覆盖在隐藏的 WebView 之上
  @Builder
  loginView() {
    Column() {
      if (this.loginIsWide()) {
        // 桌面/横屏布局（≥1024vp 或横屏 640–1023×≤520）：曲线底纹上圆角卡片，左品牌右表单
        Stack() {
          Image($rawfile('web/images/auth-frame-curves.svg'))
            .objectFit(ImageFit.Cover)
            .width('100%')
            .height('100%')
            .opacity(this.dark ? 0.02 : 0.3)
          Row() {
            this.loginBrandPanel('desktop')
            this.loginDesktopContent()
          }
          .width('100%')
          .height('100%')
          // 面板固定 stableH 高度、可能高于键盘压缩后的卡片：顶部对齐，
          // 让 wordmark/文案从卡片顶部渲染，只裁掉底部超出部分（居中会把
          // wordmark/标题挤出窗口顶部）
          .alignItems(VerticalAlign.Top)
          .constraintSize({ maxWidth: 1032, maxHeight: 780 })
          .borderRadius(24)
          .clip(true)
          .backgroundColor(this.authCardBg())
        }
        .width('100%')
        .height('100%')
        .backgroundColor(this.authPageBg())
        .padding(this.rootW >= 1024 ? 40 : {
          left: 16,
          right: 16,
          top: Math.max(16, this.topInset),
          bottom: Math.max(16, this.safeB),
        })
      } else if (this.loginIsMid()) {
        // 平板布局（640–1023vp）：40px 边距内 268px 品牌带 + 上叠 32px 的圆角工作表
        Stack() {
          Image($rawfile('web/images/auth-frame-curves.svg'))
            .objectFit(ImageFit.Cover)
            .width('100%')
            .height('100%')
            .opacity(this.dark ? 0.02 : 0.3)
          Stack({ alignContent: Alignment.Top }) {
            this.loginBrandPanel('tablet')
            this.loginOverlaySheet('tablet')
          }
          .width('100%')
          .height('100%')
          .borderRadius(24)
          .clip(true)
          .backgroundColor(this.authCardBg())
        }
        .width('100%')
        .height('100%')
        .backgroundColor(this.authPageBg())
        .padding({ left: 40, right: 40, top: Math.max(40, this.topInset), bottom: 40 })
      } else {
        // 手机布局（<640vp）：全屏 196px 品牌带 + 上叠 28px 的白色圆角底部工作表
        Stack({ alignContent: Alignment.Top }) {
          this.loginBrandPanel('mobile')
          this.loginOverlaySheet('mobile')
        }
        .width('100%')
        .height('100%')
        .backgroundColor(this.authCardBg())
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor(this.authPageBg())
  }

  private toast(msg: string): void {
    promptAction.showToast({ message: msg, duration: 2000 });
  }

  private openAdd(): void {
    this.editId = '';
    this.formIssuer = '';
    this.formAccount = '';
    this.formSecret = '';
    this.formDigits = '6';
    this.formPeriod = '30';
    this.formAlg = 0;
    this.formNote = '';
    this.formTags = [];
    this.secretVisible = false;
    this.advancedOpen = false;
    this.tagForForm = false;
    this.formType = 'totp';
    this.pickOpen = false;
    this.openPage('form');
  }

  private openEdit(r: OtpRow): void {
    this.editId = r.id;
    this.formIssuer = r.issuer;
    this.formAccount = r.account;
    this.formSecret = r.secret;
    this.formDigits = r.digits.toString();
    this.formPeriod = r.period.toString();
    this.formAlg = r.algorithm === 'sha256' ? 1 : (r.algorithm === 'sha512' ? 2 : 0);
    this.formNote = r.note;
    this.formTags = r.tags.slice();
    this.secretVisible = false;
    this.advancedOpen = false;
    this.tagForForm = false;
    this.formType = r.type;
    this.pickOpen = false;
    this.openPage('form');
  }

  private typeName(): string {
    if (this.formType === 'hotp') return 'HOTP';
    if (this.formType === 'steam') return 'STEAM';
    return 'TOTP';
  }

  private applyPick(kind: number, idx: number): void {
    if (kind === 0) {
      this.formAlg = idx;
    } else {
      this.formType = idx === 0 ? 'totp' : (idx === 1 ? 'hotp' : 'steam');
    }
    this.pickOpen = false;
  }

  private isPicked(idx: number): boolean {
    if (this.pickKind === 0) return this.formAlg === idx;
    const v: string = idx === 0 ? 'totp' : (idx === 1 ? 'hotp' : 'steam');
    return this.formType === v;
  }

  private algName(): string {
    if (this.formAlg === 1) return 'SHA256';
    if (this.formAlg === 2) return 'SHA512';
    return 'SHA1';
  }

  private async saveForm(): Promise<void> {
    if (this.bridge === null) return;
    const secret: string = this.formSecret.replace(/\s+/g, '').toUpperCase();
    if (secret.length === 0) {
      this.toast(this.tr('密钥不能为空'));
      return;
    }
    if (this.formIssuer.trim().length === 0 && this.formAccount.trim().length === 0) {
      this.toast(this.tr('发行方和账户均不能为空'));
      return;
    }
    const digits: number = parseInt(this.formDigits, 10);
    const period: number = parseInt(this.formPeriod, 10);
    let args: string = '{"issuer":' + JSON.stringify(this.formIssuer.trim()) +
      ',"account":' + JSON.stringify(this.formAccount.trim()) +
      ',"secret":' + JSON.stringify(secret) +
      ',"digits":' + (isNaN(digits) ? 6 : digits) +
      ',"period":' + (isNaN(period) ? 30 : period) +
      ',"algorithm":"' + this.algName() + '","type":' + JSON.stringify(this.formType);
    if (this.editId.length > 0) args += ',"id":' + JSON.stringify(this.editId);
    args += '}';
    const op: string = this.editId.length > 0 ? 'update' : 'add';
    this.pathStack.pop();
    try {
      const r: BridgeResult = await this.bridge.call(op, args);
      hilog.info(0x0000, TAG, 'save %{public}s ok=%{public}s err=%{public}s payload=%{public}s',
        op, r.ok.toString(), r.error, r.payload);
      if (!r.ok) {
        this.notice = this.tr('出了点问题，请重试');
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      // 备注与标签：新增时用服务端返回的 id 补齐
      let savedId: string = this.editId;
      if (savedId.length === 0 && r.payload.length > 0) {
        try {
          const added: OtpRow[] = rowsFromPayload('[' + r.payload + ']');
          if (added.length > 0) savedId = added[0].id;
        } catch (e) {
          // 解析失败则跳过备注/标签
        }
      }
      if (savedId.length > 0 && this.formNote.length > 0) {
        await this.bridge.call('setNote', '{"id":' + JSON.stringify(savedId) +
          ',"note":' + JSON.stringify(this.formNote) + '}');
      }
      if (savedId.length > 0 && (this.formTags.length > 0 || this.editId.length > 0)) {
        await this.bridge.call('setTags', '{"id":' + JSON.stringify(savedId) +
          ',"tags":' + JSON.stringify(this.formTags) + '}');
      }
      // 先用服务端返回的行刷新本地，避免列表滞后
      if (r.payload.length > 0) {
        try {
          const arr: OtpRow[] = rowsFromPayload('[' + r.payload + ']');
          if (arr.length > 0) this.upsertRow(arr[0]);
        } catch (e) {
          // 刷新失败则等待下一次全量同步
        }
      }
      if (op === 'add') {
        this.toast(this.tr('已添加'));
      }
      this.requestList(true);
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    }
  }

  private async scan(): Promise<void> {
    if (this.ctx === null) return;
    try {
      const options: scanBarcode.ScanOptions = {
        scanTypes: [scanCore.ScanType.ALL],
        enableMultiMode: false,
        enableAlbum: true,
      };
      const result: scanBarcode.ScanResult = await scanBarcode.startScanForResult(this.ctx, options);
      this.fillFromUri(result.originalValue);
    } catch (e) {
      hilog.error(0x0000, TAG, 'scan failed: %{public}s', (e as Error).message);
    }
  }

  private fillFromUri(uri: string): void {
    const parsed: OtpRow | null = parseOtpUri(uri);
    if (parsed === null) {
      this.toast(this.tr('扫描的二维码不是有效的双重认证账户。'));
      return;
    }
    this.formIssuer = parsed.issuer;
    this.formAccount = parsed.account;
    this.formSecret = parsed.secret;
    this.formDigits = parsed.digits.toString();
    this.formPeriod = parsed.period.toString();
    this.formAlg = parsed.algorithm === 'sha256' ? 1 : (parsed.algorithm === 'sha512' ? 2 : 0);
    // 从主界面扫码时打开表单页；已在表单页则只回填字段
    if (this.pathStack.size() === 0) {
      this.openPage('form');
    }
  }

  // ---------- 多语言（词条来自官方 app 的 arb 翻译） ----------

  private loadI18n(): void {
    try {
      if (this.ctx === null) return;
      // 官方 arb 转换词条与自建词条分文件维护：先加载官方，再叠加自建（同名时自建优先）
      const files: string[] = ['i18n/official.json', 'i18n/custom.json'];
      this.i18nData.clear();
      for (let f = 0; f < files.length; f++) {
        const raw: Uint8Array = this.ctx.resourceManager.getRawFileContentSync(files[f]);
        const txt: string = new util.TextDecoder('utf-8').decodeToString(raw);
        const parsed: Record<string, Record<string, string>> =
          JSON.parse(txt) as Record<string, Record<string, string>>;
        const srcList: string[] = Object.keys(parsed);
        for (let i = 0; i < srcList.length; i++) {
          const src: string = srcList[i];
          const per: Record<string, string> = parsed[src];
          let m: Map<string, string> | undefined = this.i18nData.get(src);
          if (m === undefined) {
            m = new Map<string, string>();
            this.i18nData.set(src, m);
          }
          const locList: string[] = Object.keys(per);
          for (let j = 0; j < locList.length; j++) {
            m.set(locList[j], per[locList[j]]);
          }
        }
      }
    } catch (e) {
      hilog.error(0x0000, TAG, 'i18n load failed: %{public}s', JSON.stringify(e));
    }
  }

  private systemLocale(): string {
    let lang: string = '';
    try {
      lang = i18n.System.getSystemLanguage().toLowerCase();
    } catch (e) {
      lang = '';
    }
    if (lang.indexOf('zh') === 0) {
      const hant: boolean = lang.indexOf('hant') >= 0 || lang.indexOf('tw') >= 0 ||
        lang.indexOf('hk') >= 0 || lang.indexOf('mo') >= 0;
      return hant ? 'zh_TW' : 'zh_CN';
    }
    for (let i = 0; i < LOCALE_CODES.length; i++) {
      const code: string = LOCALE_CODES[i];
      const idx: number = code.indexOf('_');
      const base: string = idx >= 0 ? code.substring(0, idx) : code;
      if (base === lang) return code;
    }
    return 'en';
  }

  private localeName(code: string): string {
    const m: Map<string, string> | undefined = this.i18nData.get('@localeName');
    if (m === undefined) return code;
    const v: string | undefined = m.get(code);
    return v === undefined ? code : v;
  }

  private setLocale(code: string): void {
    this.locale = code;
    if (this.store !== null) {
      this.store.put(KEY_LOCALE, code);
    }
    this.localeRev++;
    this.applyStatusBar();
  }

  // 统一取词：以中文原文为键，缺失时回退英文，再回退原文
  private tr(src: string): string {
    const rev: number = this.localeRev; // 读取 @State，语言切换后自动重建
    if (rev < 0 || this.i18nData.size === 0) return src;
    const m: Map<string, string> | undefined = this.i18nData.get(src);
    if (m === undefined) return src;
    const v: string | undefined = m.get(this.locale);
    if (v !== undefined && v.length > 0) return v;
    const ev: string | undefined = m.get('en');
    return ev !== undefined && ev.length > 0 ? ev : src;
  }

  // ICU 复数词条：解析 {count, plural, cat{text}...} 各分支（支持 few/many 等类别、
  // 分支内嵌 {count} 占位符），按 count 选分支并替换占位符
  private icuPlural(src: string, count: number): string {
    const raw: string = this.tr(src);
    const re: RegExp = /(?:^|[^a-zA-Z])(one|zero|two|few|many|other)\{((?:[^{}]|\{count\})*)\}/g;
    let one: string = '';
    let other: string = '';
    let first: string = '';
    let m: RegExpExecArray | null = re.exec(raw);
    while (m !== null) {
      if (first.length === 0) {
        first = m[2];
      }
      if (m[1] === 'one') {
        one = m[2];
      } else if (m[1] === 'other') {
        other = m[2];
      }
      m = re.exec(raw);
    }
    if (first.length === 0) {
      return raw.replace('{count}', count.toString());
    }
    const branch: string = count === 1 && one.length > 0 ? one : (other.length > 0 ? other : first);
    return branch.replace('{count}', count.toString());
  }

  // 二级页面入栈（Navigation Stack，自带返回）
  private openPage(name: string): void {
    // 保留抽屉展开状态：页面压在抽屉之上，返回后抽屉仍在
    this.searchOpen = false;
    this.fabOpen = false;
    this.menuId = '';
    this.exitSelection();
    this.pageName = name;
    this.pathStack.pushPathByName(name, null);
    if (name === 'security') {
      this.loadEmailMfa();
    }
  }

  // NavDestination 的内容只在入栈时构建一次，修改设置后需要重建当前页才能刷新文案/勾选态
  private refreshCurrentPage(): void {
    if (this.pageName.length === 0 || this.pathStack.size() === 0) return;
    try {
      this.pathStack.replacePathByName(this.pageName, null);
    } catch (e) {
      // 忽略重建失败
    }
  }

  private openQr(r: OtpRow): void {
    this.qrUri = r.uri.length > 0 ? r.uri : this.titleOf(r) + ':' + r.secret;
    this.qrTitle = this.titleOf(r);
    this.openPage('qrcode');
  }

  // 系统分享面板在当前 SDK 不可用，退化为复制 otpauth 链接，可粘贴到任意应用分享
  private async shareRow(r: OtpRow): Promise<void> {
    const txt: string = r.uri.length > 0 ? r.uri : this.titleOf(r) + ' ' + this.codeOf(r);
    if (await this.systemShareText(txt, this.titleOf(r))) return;
    // 系统分享不可用时退化为复制，可粘贴到任意应用分享
    try {
      const data: pasteboard.PasteData = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, txt);
      await pasteboard.getSystemPasteboard().setData(data);
      this.toast(this.tr('已复制到剪贴板'));
    } catch (e) {
      hilog.error(0x0000, TAG, 'share copy failed: %{public}s', (e as Error).message);
    }
  }

  private codeOf(r: OtpRow): string {
    return this.formatCode(r.code);
  }

  private openNote(r: OtpRow): void {
    this.menuId = '';
    this.noteId = r.id;
    this.noteText = r.note;
    this.noteOpen = true;
  }

  private async saveNote(): Promise<void> {
    if (this.bridge === null) return;
    const id: string = this.noteId;
    const note: string = this.noteText;
    this.noteOpen = false;
    this.noteId = '';
    try {
      const res: BridgeResult = await this.bridge.call('setNote',
        '{"id":' + JSON.stringify(id) + ',"note":' + JSON.stringify(note) + '}');
      if (!res.ok) {
        hilog.error(0x0000, TAG, 'setNote failed: %{public}s', res.error);
        return;
      }
      this.requestList(true);
    } catch (e) {
      hilog.error(0x0000, TAG, 'setNote error: %{public}s', (e as Error).message);
    }
  }

  private setAppLock(v: boolean): void {
    this.appLock = v;
    if (this.store !== null) {
      this.store.put(KEY_APPLOCK, v ? '1' : '0');
    }
    if (v) {
      Biometrics.verify(this.tr('请验证')).then((ok: boolean) => {
        this.bioOk = ok;
      });
    }
  }

  private setBigIcons(v: boolean): void {
    this.bigIcons = v;
    if (this.store !== null) {
      this.store.put(KEY_BIG_ICONS, v ? '1' : '0');
    }
  }

  private setCompact(v: boolean): void {
    this.compact = v;
    if (this.store !== null) {
      this.store.put(KEY_COMPACT, v ? '1' : '0');
    }
  }

  private setCopyMinimize(v: boolean): void {
    this.copyMinimize = v;
    if (this.store !== null) {
      this.store.put(KEY_COPY_MIN, v ? '1' : '0');
    }
  }

  // ---------- 账户 / 安全：直接复用网页登录态调用 Ente API ----------

  private async loadRecoveryKey(): Promise<void> {
    if (this.bridge === null) return;
    this.acctBusy = true;
    try {
      const res: BridgeResult = await this.bridge.call('recoveryKey', '{}');
      if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      const p: RecoveryPayload = JSON.parse(res.payload) as RecoveryPayload;
      this.recoveryWords = p.mnemonic;
      this.recoveryOpen = true;
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.acctBusy = false;
    }
  }

  private openEmailSheet(): void {
    this.newEmail = '';
    this.emailOtt = '';
    this.emailStep = 0;
    this.emailOpen = true;
  }

  private async sendEmailOtt(): Promise<void> {
    if (this.bridge === null) return;
    const email: string = this.newEmail.trim();
    if (email.length === 0 || email.indexOf('@') < 0) {
      this.toast(this.tr('请输入有效的电子邮件地址。'));
      return;
    }
    this.acctBusy = true;
    try {
      const res: BridgeResult = await this.bridge.call('sendChangeEmailOtt',
        '{"email":' + JSON.stringify(email) + '}');
      if (!res.ok) {
        this.toast(res.error.indexOf('http_409') >= 0
          ? this.tr('此电子邮件已被使用') : this.tr('出了点问题，请重试'));
        return;
      }
      this.emailStep = 1;
      this.toast(this.tr('@weHaveSentCode').replace('{email}', email));
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.acctBusy = false;
    }
  }

  private async confirmChangeEmail(): Promise<void> {
    if (this.bridge === null) return;
    const email: string = this.newEmail.trim();
    const ott: string = this.emailOtt.trim();
    this.acctBusy = true;
    try {
      const res: BridgeResult = await this.bridge.call('changeEmail',
        '{"email":' + JSON.stringify(email) + ',"ott":' + JSON.stringify(ott) + '}');
      if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      this.userEmail = email;
      this.emailOpen = false;
      this.toast(this.tr('@emailChangedTo').replace('{newEmail}', email));
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.acctBusy = false;
    }
  }

  private async confirmDeleteAccount(): Promise<void> {
    if (this.bridge === null) return;
    try {
      const r: promptAction.ShowDialogSuccessResponse = await promptAction.showDialog({
        title: this.tr('要永久删除您的 Ente 账户吗？'),
        message: this.tr('您在 Ente Photos、Ente Auth 和 Ente Locker 中共用一个账户。'),
        buttons: [
          { text: this.tr('取消'), color: this.muted() },
          { text: this.tr('永久删除'), color: '#F53434' },
        ],
      });
      if (r.index !== 1) return;
      this.acctBusy = true;
      const res: BridgeResult = await this.bridge.call('deleteAccount', '{}');
      if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      await this.logout();
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.acctBusy = false;
    }
  }

  private async openSessions(): Promise<void> {
    if (this.bridge === null) return;
    this.sessions = [];
    this.sessionsOpen = true;
    this.sessionsLoading = true;
    try {
      const res: BridgeResult = await this.bridge.call('sessions', '{}');
      if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      const p: SessionsPayload = JSON.parse(res.payload) as SessionsPayload;
      this.sessions = p.sessions;
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.sessionsLoading = false;
    }
  }

  private async terminateSession(token: string): Promise<void> {
    if (this.bridge === null) return;
    try {
      const res: BridgeResult = await this.bridge.call('terminateSession',
        '{"token":' + JSON.stringify(token) + '}');
      if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      await this.openSessions();
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    }
  }

  // 在应用内打开官方账户页面（同一 WebView，保留登录态，完成后返回原生界面）
  private async openWebAccountPage(path: string, title: string): Promise<void> {
    this.drawerOpen = false;
    // 请求校验期间先隐藏 WebView，用原生紫色加载圈给出反馈
    this.webLoading = true;
    // 官方修改密码页依赖网页端完整的本地账户状态（user + keyAttributes）。
    // 状态残缺时网页会 stashRedirect 跳回登录页并卡在加载中（闪一下登录页后一直转圈），
    // 因此先校验并修补；无法修补说明登录态已损坏，直接走完整退出登录。
    if (this.bridge !== null) {
      let ready: boolean = true;
      try {
        const call: Promise<BridgeResult> = this.bridge.call('ensureUser', '{}');
        // 页面导航中 runJavaScriptExt 可能长时间不返回，超时后按可用处理，避免加载圈卡死
        const guard: Promise<BridgeResult> = new Promise<BridgeResult>(
          (resolve: (r: BridgeResult) => void) => {
            setTimeout(() => resolve(new BridgeResult()), 6000);
          });
        const res: BridgeResult = await Promise.race([call, guard]);
        if (res.ok) {
          const p: UserReadyPayload = JSON.parse(res.payload) as UserReadyPayload;
          ready = p.ready === true;
        }
      } catch (e) {
        hilog.error(0x0000, TAG, 'ensureUser failed: %{public}s', (e as Error).message);
      }
      if (!ready) {
        // 状态无法修补：保持隐藏状态直接切到登录页，等登录页加载完成再撤掉加载圈
        await this.logout();
        this.toast(this.tr('您的会话已过期。请重新登录。'));
        return;
      }
    }
    this.webPageTitle = title;
    this.webPageOpen = true;
    this.webTargetUrl = 'https://auth.ente.com' + path;
    this.webTargetBase = this.webTargetUrl;
    try {
      // 标记当前是账户页：修改密码成功后网页会跳到 /auth，此时不要再被防闪屏守卫遮挡
      if (this.bridge !== null) {
        await this.bridge.exec("try{sessionStorage.setItem('__enteAccountPage','1');}catch(e){}");
      }
      this.controller.loadUrl(this.webTargetUrl);
    } catch (e) {
      this.webPageOpen = false;
      this.webLoading = false;
      this.webTargetUrl = '';
      this.webTargetBase = '';
      this.toast(this.tr('出了点问题，请重试'));
    }
  }

  private closeWebAccountPage(): void {
    this.webPageOpen = false;
    this.webReady = false;
    this.webTargetUrl = '';
    this.webTargetBase = '';
    try {
      this.controller.loadUrl(START_URL);
    } catch (e) {
      // onTick 会自动重载
    }
  }

  // 在应用内打开任意官方页面（通行密钥等外部账户页面）
  private openWebUrl(url: string, title: string): void {
    this.drawerOpen = false;
    this.webPageTitle = title;
    this.webPageOpen = true;
    // 加载期间用原生加载圈盖住旧页面残留与白屏，页面加载完成（onPageEnd）后自动撤掉
    this.webLoading = true;
    this.webTargetUrl = url;
    const q: number = url.indexOf('?');
    this.webTargetBase = q >= 0 ? url.substring(0, q) : url;
    hilog.info(0x0000, TAG, 'openWebUrl: %{public}s', url);
    try {
      this.controller.loadUrl(url);
    } catch (e) {
      this.webPageOpen = false;
      this.webLoading = false;
      this.webTargetUrl = '';
      this.webTargetBase = '';
      this.toast(this.tr('出了点问题，请重试'));
    }
  }

  // 通行密钥：与官方一致，取带 accounts token 的管理页地址后打开
  private openPasskeys(): void {
    if (this.bridge === null) return;
    this.requireAuth(() => {
      this.loadPasskeyUrl();
    });
  }

  // 官方网页使用 IndexedDB 的 kv 库；若此前被写入过没有 object store 的同版本空库，
  // 网页会一直报 NotFoundError，这里检测并重建一次。
  // 注意：只能在库已存在且损坏时修复——indexedDB.open 会隐式创建空库，
  // 若库不存在就探测会与应用自身初始化竞态，造成 删库→重载→再建空库 的无限重载循环
  // （表现为通行密钥页面反复闪烁刷新、加载不出来）。
  private async repairWebKv(): Promise<void> {
    const script: string =
      "setTimeout(function(){try{" +
      // 每个会话最多修复一次，即使修复后仍异常也不再重载
      "if(sessionStorage.getItem('__kvRepairDone'))return;" +
      // databases() 返回 Promise；库不存在时直接返回，绝不创建
      "if(!indexedDB.databases)return;" +
      "indexedDB.databases().then(function(list){var has=false;" +
      "for(var i=0;i<list.length;i++){if(list[i].name==='kv'){has=true;break;}}" +
      "if(!has)return;" +
      "var r=indexedDB.open('kv');" +
      "r.onsuccess=function(){var db=r.result;var broken=!db.objectStoreNames.contains('kv');" +
      "try{db.close();}catch(e){}" +
      "if(broken){sessionStorage.setItem('__kvRepairDone','1');" +
      "indexedDB.deleteDatabase('kv').onsuccess=function(){location.reload();};}" +
      "};}).catch(function(){});" +
      "}catch(e){}},1500);";
    try {
      await this.controller.runJavaScript(script);
    } catch (e) {
      // 页面尚未就绪时忽略
    }
  }

  private async loadPasskeyUrl(): Promise<void> {
    if (this.bridge === null) return;
    try {
      const res: BridgeResult = await this.bridge.call('passkeyUrl', '{}');
      hilog.info(0x0000, TAG, 'passkeyUrl res: %{public}s', res.payload);
      if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      const p: PasskeyUrlPayload = JSON.parse(res.payload) as PasskeyUrlPayload;
      if (p.url.length === 0) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      this.openWebUrl(p.url, this.tr('通行密钥'));
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    }
  }

  private async loadEmailMfa(): Promise<void> {
    if (this.bridge === null) return;
    this.emailMfaLoading = true;
    try {
      const res: BridgeResult = await this.bridge.call('emailMfaStatus', '{}');
      if (!res.ok) return;
      const p: EmailMfaPayload = JSON.parse(res.payload) as EmailMfaPayload;
      const changed: boolean = p.enabled !== this.emailMfaEnabled || p.canDisable !== this.emailMfaCanDisable;
      this.emailMfaEnabled = p.enabled;
      this.emailMfaCanDisable = p.canDisable;
      if (changed && this.pageName === 'security') {
        this.refreshCurrentPage();
      }
    } catch (e) {
      // 读取失败时保持默认（关闭）
    } finally {
      this.emailMfaLoading = false;
    }
  }

  private onEmailMfaToggle(v: boolean): void {
    this.emailMfaEnabled = v;
    this.requireAuth(() => {
      if (v) {
        this.emailMfaWarnOpen = true;
      } else if (!this.emailMfaCanDisable) {
        this.emailMfaEnabled = true;
        this.toast(this.tr('请先在官方网页端验证密码后再关闭电子邮件验证'));
      } else {
        this.applyEmailMfa(false);
      }
    });
  }

  private async applyEmailMfa(enable: boolean): Promise<void> {
    if (this.bridge === null) return;
    this.emailMfaLoading = true;
    try {
      const res: BridgeResult = await this.bridge.call('setEmailMfa',
        '{"enabled":' + (enable ? 'true' : 'false') + '}');
      if (!res.ok) {
        this.emailMfaEnabled = !enable;
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      this.emailMfaEnabled = enable;
      this.refreshCurrentPage();
    } catch (e) {
      this.emailMfaEnabled = !enable;
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.emailMfaLoading = false;
    }
  }

  private sessionLabel(s: SessionInfo): string {
    if (s.prettyUA.length > 0) return s.prettyUA;
    return s.ua;
  }

  private async openUrl(url: string): Promise<void> {
    if (this.ctx === null) return;
    try {
      const abilityCtx: common.UIAbilityContext = this.ctx as common.UIAbilityContext;
      await abilityCtx.startAbility({ action: 'ohos.want.action.viewData', uri: url });
    } catch (e) {
      hilog.error(0x0000, TAG, 'openUrl failed: %{public}s', (e as Error).message);
    }
  }

  // 同意隐私政策后才创建 WebView，之后不再重复提示
  private acceptPrivacy(): void {
    if (this.store !== null) {
      this.store.put(KEY_PRIVACY, '1');
    }
    this.privacyAccepted = true;
  }

  // 拒绝同意：直接退出应用
  private exitApp(): void {
    if (this.ctx === null) return;
    const abilityCtx: common.UIAbilityContext = this.ctx as common.UIAbilityContext;
    abilityCtx.terminateSelf();
  }

  // ---------- 本地打包的官方 web：按 URL 从 rawfile 返回，未知资源回退网络 ----------

  private localAssetPath(url: string): string {
    const prefix: string = 'https://auth.ente.com';
    if (!url.startsWith(prefix)) return '';
    let p: string = url.substring(prefix.length);
    const q: number = p.indexOf('?');
    if (q >= 0) p = p.substring(0, q);
    const h: number = p.indexOf('#');
    if (h >= 0) p = p.substring(0, h);
    if (p.length === 0 || p === '/') return 'web/index.html';
    if (p.startsWith('/_next/') || p.startsWith('/images/')) return 'web' + p;
    // 官方路由（change-password / credentials 等）随包提供静态 HTML
    if (p.indexOf('.') < 0) {
      const route: string = p.endsWith('/') ? p.substring(0, p.length - 1) : p;
      return 'web' + route + '/index.html';
    }
    return '';
  }

  private mimeOf(path: string): string {
    if (path.endsWith('.js')) return 'application/javascript';
    if (path.endsWith('.css')) return 'text/css';
    if (path.endsWith('.html')) return 'text/html';
    if (path.endsWith('.json')) return 'application/json';
    if (path.endsWith('.wasm')) return 'application/wasm';
    if (path.endsWith('.png')) return 'image/png';
    if (path.endsWith('.svg')) return 'image/svg+xml';
    if (path.endsWith('.woff2')) return 'font/woff2';
    if (path.endsWith('.woff')) return 'font/woff';
    if (path.endsWith('.ico')) return 'image/x-icon';
    return 'application/octet-stream';
  }

  private interceptRequest(event: OnInterceptRequestEvent): WebResourceResponse | null {
    if (this.ctx === null) return null;
    try {
      const url: string = event.request.getRequestUrl();
      const path: string = this.localAssetPath(url);
      if (path.length === 0) return null;
      const raw: Uint8Array = this.ctx.resourceManager.getRawFileContentSync(path);
      if (raw.length === 0) return null;
      const buf: ArrayBuffer = new ArrayBuffer(raw.length);
      const view: Uint8Array = new Uint8Array(buf);
      view.set(raw);
      const res: WebResourceResponse = new WebResourceResponse();
      res.setResponseMimeType(this.mimeOf(path));
      // wasm 为二进制，不能声明文本编码，否则 instantiateStreaming 会失败
      if (!path.endsWith('.wasm')) {
        res.setResponseEncoding('utf-8');
      }
      res.setResponseCode(200);
      res.setResponseData(buf);
      res.setResponseIsReady(true);
      return res;
    } catch (e) {
      return null;
    }
  }

  // 重复验证码：issuer + 账号 + 密钥 + 位数 + 周期 + 算法 相同视为重复
  private dupGroups(): Map<string, OtpRow[]> {
    const groups: Map<string, OtpRow[]> = new Map<string, OtpRow[]>();
    for (const r of this.rows) {
      if (r.trashed) continue;
      const k: string = r.issuer + '|' + r.account + '|' + r.secret + '|' +
        r.digits + '|' + r.period + '|' + r.algorithm;
      const list: OtpRow[] | undefined = groups.get(k);
      if (list === undefined) {
        groups.set(k, [r]);
      } else {
        list.push(r);
      }
    }
    return groups;
  }

  private dupGroupList(): OtpRow[][] {
    const out: OtpRow[][] = [];
    this.dupGroups().forEach((list: OtpRow[]) => {
      if (list.length > 1) out.push(list);
    });
    return out;
  }

  private openDuplicates(): void {
    if (this.dupGroupList().length === 0) {
      // 对齐官方：无重复时弹出提示对话框
      this.noDupOpen = true;
      return;
    }
    this.dupSelKeys = [];
    this.openPage('duplicates');
  }

  private toggleDupGroup(g: OtpRow[]): void {
    const k: string = g[0].id;
    const idx: number = this.dupSelKeys.indexOf(k);
    const next: string[] = this.dupSelKeys.slice();
    if (idx >= 0) {
      next.splice(idx, 1);
    } else {
      next.push(k);
    }
    this.dupSelKeys = next;
  }

  private toggleDupAll(): void {
    const groups: OtpRow[][] = this.dupGroupList();
    if (this.dupSelKeys.length === groups.length) {
      this.dupSelKeys = [];
      return;
    }
    const all: string[] = [];
    for (const g of groups) {
      all.push(g[0].id);
    }
    this.dupSelKeys = all;
  }

  private dupSelectedExtras(): number {
    let n: number = 0;
    for (const g of this.dupGroupList()) {
      if (this.dupSelKeys.indexOf(g[0].id) >= 0) n += g.length - 1;
    }
    return n;
  }

  // 对齐官方：勾选组内除最早一条外全部移入回收站
  private async trashSelectedDuplicates(): Promise<void> {
    if (this.bridge === null) return;
    this.dupConfirmOpen = false;
    const sel: string[] = this.dupSelKeys;
    for (const g of this.dupGroupList()) {
      if (sel.indexOf(g[0].id) < 0) continue;
      for (let i = 1; i < g.length; i++) {
        await this.bridge.call('setTrashed',
          '{"id":' + JSON.stringify(g[i].id) + ',"trashed":true}');
      }
    }
    this.dupSelKeys = [];
    this.pathStack.pop();
    this.toast(this.tr('已移至回收站'));
    this.requestList(true);
  }

  private async togglePin(r: OtpRow): Promise<void> {
    if (this.bridge === null) return;
    this.menuId = '';
    const r2: BridgeResult = await this.bridge.call('setPinned',
      '{"id":' + JSON.stringify(r.id) + ',"pinned":' + (r.pinned ? 'false' : 'true') + '}');
    if (!r2.ok) {
      this.toast(this.tr('出了点问题，请重试'));
      return;
    }
    this.requestList(true);
  }

  private async toggleTrash(r: OtpRow): Promise<void> {
    if (this.bridge === null) return;
    this.menuId = '';
    const r2: BridgeResult = await this.bridge.call('setTrashed',
      '{"id":' + JSON.stringify(r.id) + ',"trashed":' + (r.trashed ? 'false' : 'true') + '}');
    if (!r2.ok) {
      this.toast(this.tr('出了点问题，请重试'));
      return;
    }
    // 文案取自官方词条：restoredItems / movedToTrash
    this.toast(r.trashed ? this.icuPlural('@restoredItems', 1) : this.tr('已移至回收站'));
    this.requestList(true);
  }

  private async removeRowById(id: string): Promise<void> {
    if (this.bridge === null) return;
    const res: BridgeResult = await this.bridge.call('remove', '{"id":' + JSON.stringify(id) + '}');
    if (!res.ok) {
      this.toast(this.tr('出了点问题，请重试'));
      return;
    }
    const out: OtpRow[] = [];
    for (const x of this.rows) {
      if (x.id !== id) out.push(x);
    }
    this.rows = out;
    this.saveCache();
    this.requestList(true);
  }

  private async exportAll(): Promise<void> {
    const lines: string[] = [];
    for (const r of this.rows) {
      if (!r.trashed && !r.broken && r.uri.length > 0) lines.push(r.uri);
    }
    if (lines.length === 0) {
      this.toast(this.tr('没有可导出的条目'));
      return;
    }
    const data: pasteboard.PasteData = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, lines.join('\n'));
    await pasteboard.getSystemPasteboard().setData(data);
    this.pathStack.pop();
    this.toast(this.tr('已复制到剪贴板'));
  }

  // ---------- 导出（对齐官方：加密 JSON / 纯文本 / HTML） ----------

  private exportableUris(): string[] {
    const out: string[] = [];
    for (const r of this.rows) {
      if (!r.trashed && !r.broken && r.uri.length > 0) out.push(r.uri);
    }
    return out;
  }

  private openExport(): void {
    this.exportStep = 0;
    this.exportPwd = '';
    this.exportFormat = 'encrypted';
    this.exportOpen = true;
  }

  private stamp(): string {
    const d: Date = new Date();
    const p2 = (n: number): string => (n < 10 ? '0' : '') + n.toString();
    return d.getFullYear().toString() + p2(d.getMonth() + 1) + p2(d.getDate()) +
      '-' + p2(d.getHours()) + p2(d.getMinutes()) + p2(d.getSeconds());
  }

  // 对齐官方文件名：ente-auth-codes-<type>-yyyyMMdd-HHmmss.<ext>
  private exportName(): string {
    const kind: string = this.exportFormat === 'encrypted' ? 'encrypted'
      : (this.exportFormat === 'html' ? 'plainhtml' : 'plaintext');
    const ext: string = this.exportFormat === 'encrypted' ? 'json'
      : (this.exportFormat === 'html' ? 'html' : 'txt');
    return 'ente-auth-codes-' + kind + '-' + this.stamp() + '.' + ext;
  }

  private async writeDocument(name: string, content: string): Promise<boolean> {
    if (this.ctx === null) return false;
    try {
      const p: picker.DocumentViewPicker = new picker.DocumentViewPicker(this.ctx);
      const opt: picker.DocumentSaveOptions = new picker.DocumentSaveOptions();
      opt.newFileNames = [name];
      const uris: string[] = await p.save(opt);
      if (uris === undefined || uris.length === 0) return false;
      const f: fileIo.File = fileIo.openSync(uris[0],
        fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE | fileIo.OpenMode.TRUNC);
      try {
        fileIo.writeSync(f.fd, content);
      } finally {
        fileIo.closeSync(f);
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  private buildHtml(): string {
    let s: string = '<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">';
    s += '<meta name="viewport" content="width=device-width,initial-scale=1">';
    s += this.tr('<title>Ente Auth 验证码导出</title><style>');
    s += 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:32px;background:#fafafa;color:#18181b}';
    s += 'h1{font-size:22px;margin:0 0 6px}p{color:#71717a;font-size:12px;margin:0 0 20px}';
    s += 'table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;font-size:14px}';
    s += 'th,td{padding:12px 14px;text-align:left;border-bottom:1px solid #f0f0f2}';
    s += 'th{background:#f6f6f8;font-weight:600;font-size:12px;color:#52525b}';
    s += 'code{font-family:ui-monospace,Menlo,Consolas,monospace;letter-spacing:1px}';
    s += this.tr('</style></head><body><h1>Ente Auth 验证码导出</h1>');
    s += this.tr('<p>共 ') + this.exportableUris().length.toString() + this.tr(' 条 · 导出时间 ') + this.stamp() +
      this.tr(' · 仅包含密钥，不包含当前动态码</p>');
    s += this.tr('<table><tr><th>服务</th><th>账号</th><th>密钥</th><th>类型</th></tr>');
    for (const r of this.rows) {
      if (r.trashed || r.broken) continue;
      const typeTxt: string = r.type.toUpperCase() + ' · ' + r.digits.toString() + this.tr(' 位 / ') +
        r.period.toString() + 's';
      s += '<tr><td>' + htmlEsc(this.titleOf(r)) + '</td><td>' + htmlEsc(r.account) +
        '</td><td><code>' + htmlEsc(r.secret) + '</code></td><td>' + typeTxt + '</td></tr>';
    }
    s += '</table></body></html>';
    return s;
  }

  // 对齐官方：导出前需通过本地身份验证（开启应用锁时提示验证）
  private async runExport(): Promise<void> {
    await this.requireAuth(() => {
      this.runExportInner();
    });
  }

  private async runExportInner(): Promise<void> {
    if (this.exportBusy) return;
    const lines: string[] = this.exportableUris();
    if (lines.length === 0) {
      this.toast(this.tr('没有可导出的条目'));
      return;
    }
    this.exportBusy = true;
    try {
      let content: string = '';
      if (this.exportFormat === 'encrypted') {
        if (this.exportPwd.length < 8) {
          this.toast(this.tr('密码长度必须至少为 8 个字符。'));
          return;
        }
        if (this.bridge === null) {
          return;
        }
        const args: string = JSON.stringify({ password: this.exportPwd, plain: lines.join('\n') });
        const res: BridgeResult = await this.bridge.call('encryptExport', args, 180000);
        if (!res.ok) {
        this.toast(this.tr('出了点问题，请重试'));
        return;
      }
      content = res.payload;
      } else if (this.exportFormat === 'html') {
        content = this.buildHtml();
      } else {
        content = lines.join('\n');
      }
      const name: string = this.exportName();
      const saved: boolean = await this.writeDocument(name, content);
      if (saved) {
        this.exportOpen = false;
        this.exportStep = 0;
      } else {
        this.toast(this.tr('出了点问题，请重试'));
      }
    } catch (e) {
      this.toast(this.tr('出了点问题，请重试'));
    } finally {
      this.exportBusy = false;
    }
  }

  // ---------- 导入（对齐官方：文件导入 + Google 迁移二维码） ----------

  private async pickFileText(): Promise<string> {
    if (this.ctx === null) return '';
    try {
      const p: picker.DocumentViewPicker = new picker.DocumentViewPicker(this.ctx);
      const opt: picker.DocumentSelectOptions = new picker.DocumentSelectOptions();
      opt.maxSelectNumber = 1;
      const uris: string[] = await p.select(opt);
      if (uris === undefined || uris.length === 0) return '';
      const f: fileIo.File = fileIo.openSync(uris[0], fileIo.OpenMode.READ_ONLY);
      try {
        const stat: fileIo.Stat = fileIo.statSync(uris[0]);
        const buf: ArrayBuffer = new ArrayBuffer(stat.size);
        fileIo.readSync(f.fd, buf);
        const decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
        return decoder.decodeToString(new Uint8Array(buf));
      } finally {
        fileIo.closeSync(f);
      }
    } catch (e) {
      this.toast(this.tr('无法解析选定的文件。'));
      return '';
    }
  }

  // 从任意文本/JSON 中提取 otpauth 链接（兼容 JSON 里的 \/ 转义）
  private extractUris(text: string): string[] {
    const norm: string = text.split('\\/').join('/');
    const out: string[] = [];
    let idx: number = norm.indexOf('otpauth://');
    while (idx >= 0) {
      let end: number = idx;
      while (end < norm.length) {
        const ch: string = norm.charAt(end);
        if (ch === '"' || ch === '\n' || ch === '\r' || ch === '<' || ch === ' ' ||
          ch === '\t' || ch === ',' || ch === '\\') {
          break;
        }
        end++;
      }
      const uri: string = norm.substring(idx, end).trim();
      if (uri.length > 9) out.push(uri);
      idx = norm.indexOf('otpauth://', end);
    }
    return out;
  }

  private async doImportText(text: string): Promise<void> {
    const uris: string[] = this.extractUris(text);
    const items: OtpRow[] = [];
    for (const u of uris) {
      const p: OtpRow | null = parseOtpUri(u);
      if (p !== null) items.push(p);
    }
    if (items.length === 0) {
      this.toast(this.tr('无法解析选定的文件。'));
      return;
    }
    await this.importRows(items);
  }

  private async importRows(items: OtpRow[]): Promise<void> {
    if (this.bridge === null) return;
    let arr: string = '[';
    for (let i = 0; i < items.length; i++) {
      const it: OtpRow = items[i];
      if (i > 0) arr += ',';
      arr += '{"issuer":' + JSON.stringify(it.issuer) +
        ',"account":' + JSON.stringify(it.account) +
        ',"secret":' + JSON.stringify(it.secret) +
        ',"digits":' + it.digits +
        ',"period":' + it.period +
        ',"algorithm":"' + it.algorithm.toUpperCase() + '","type":"' + it.type + '"}';
    }
    arr += ']';
    const r: BridgeResult = await this.bridge.call('importMany', '{"items":' + arr + '}');
    if (!r.ok) {
      this.toast(this.tr('无法解析选定的文件。'));
      return;
    }
    // 对齐官方：导入成功后显示成功弹层（耶！+ 导入数量）
    this.importSuccessCount = items.length;
    this.importGuideApp = '';
    this.pathStack.pop();
    this.requestList(true);
  }

  private async importFromFile(needsPassword: boolean): Promise<void> {
    const text: string = await this.pickFileText();
    if (text.length === 0) return;
    if (needsPassword || text.indexOf('"encryptedData"') >= 0) {
      this.importFileText = text;
      this.importPwd = '';
      this.importPwdOpen = true;
      return;
    }
    await this.doImportText(text);
  }

  private async confirmImportPwd(): Promise<void> {
    if (this.bridge === null || this.importBusy) return;
    if (this.importPwd.length === 0) {
      this.toast(this.tr('输入密码'));
      return;
    }
    this.importBusy = true;
    try {
      const args: string = JSON.stringify({ password: this.importPwd, file: this.importFileText });
      const res: BridgeResult = await this.bridge.call('decryptExport', args, 180000);
      if (!res.ok) {
        this.toast(this.tr('请检查您的密码并重试。'));
        return;
      }
      const plain: string = JSON.parse(res.payload) as string;
      this.importPwdOpen = false;
      this.importFileText = '';
      await this.doImportText(plain);
    } catch (e) {
      this.toast(this.tr('请检查您的密码并重试。'));
    } finally {
      this.importBusy = false;
    }
  }

  private async importGoogleAuth(): Promise<void> {
    if (this.ctx === null) return;
    try {
      const options: scanBarcode.ScanOptions = {
        scanTypes: [scanCore.ScanType.ALL],
        enableMultiMode: false,
        enableAlbum: true,
      };
      const result: scanBarcode.ScanResult = await scanBarcode.startScanForResult(this.ctx, options);
      const uri: string = result.originalValue;
      if (uri.indexOf('otpauth-migration://') !== 0) {
        this.toast(this.tr('扫描的二维码不是有效的双重认证账户。'));
        return;
      }
      const items: OtpRow[] = parseMigrationUri(uri);
      if (items.length === 0) {
        this.toast(this.tr('无法解析选定的文件。'));
        return;
      }
      await this.importRows(items);
    } catch (e) {
      hilog.error(0x0000, TAG, 'scan migration failed: %{public}s', (e as Error).message);
    }
  }

  // ---------- 导入说明弹层（对齐官方 instruction sheet） ----------

  private importGuideTitle(app: string): string {
    if (app === 'plain') return this.tr('导入代码');
    if (app === 'ente') return 'Ente Auth';
    if (app === '2fas') return '2FAS Authenticator';
    if (app === 'aegis') return 'Aegis Authenticator';
    if (app === 'andotp') return 'andOTP';
    if (app === 'openauth') return 'Open Authenticator';
    if (app === 'bitwarden') return 'Bitwarden';
    if (app === 'ga') return 'Google Authenticator';
    if (app === 'proton') return 'Proton Authenticator';
    if (app === 'raivo') return 'Raivo OTP';
    if (app === 'lastpass') return 'LastPass Authenticator';
    if (app === 'otpauth') return 'OTP Auth';
    return '';
  }

  private importGuideBody(app: string): string {
    if (app === 'plain') return this.tr('请选择一个包含以下格式的代码列表的文件');
    if (app === 'ente') return this.tr('选择从 Ente 导出的 JSON 加密文件');
    if (app === '2fas') return this.tr('使用 2FAS 中的“设置 -> 备份 -> 导出”选项。\n\n如果您的备份已加密，则需要输入密码来解密备份');
    if (app === 'aegis') return this.tr('使用 Aegis 设置中的“导出密码库”选项。\n\n如果您的密码库已加密，则需要输入密码库密码才能解密密码库。');
    if (app === 'andotp') return this.tr('使用设置中的“备份”选项从 andOTP 导出您的备份。\n\n如果您的备份已加密，您需要输入备份密码才能解密。');
    if (app === 'openauth') return this.tr('使用 Open Authenticator 设置中的“备份”选项创建备份，然后分享或导出。\n\n您需要输入创建备份时设置的密码。');
    if (app === 'bitwarden') return this.tr('使用 Bitwarden 工具中的“导出密码库”选项并导入未加密的 JSON 文件。');
    if (app === 'ga') return this.tr('使用“转移帐号”选项，将您的 Google Authenticator 账户导出到二维码。然后扫描二维码或从图像导入。');
    if (app === 'proton') return this.tr('使用 Proton Authenticator 设置中的“导出”选项导出您的验证码。\n\n如果导出的文件受密码保护，您需要输入密码才能解密。');
    if (app === 'raivo') return this.tr('使用 Raivo 设置中的“将 OTP 导出到 Zip 存档”选项。\n\n解压 zip 文件并导入 JSON 文件。');
    if (app === 'lastpass') return this.tr('使用 LastPass Authenticator 设置中的“转移账户”选项，然后点击“将账户导出到文件”。导入下载的 JSON 文件。');
    if (app === 'otpauth') return this.tr('从 OTP Auth 导出加密备份，然后选择 .otpauthdb 或 .otpauthdp 文件。也支持单个账户的 .otpauth 文件导出。');
    return '';
  }

  // 动作按钮文案（对齐官方：选择文件 / 选择 JSON 文件 / 选择 xx 的导出文件 / 扫描二维码）
  private importGuideAction(app: string): string {
    if (app === 'plain' || app === 'openauth') return this.tr('选择文件');
    if (app === 'ga') return this.tr('扫描二维码');
    if (app === '2fas') return this.tr('@importSelectAppExport').replace('{appName}', '2FAS Authenticator');
    if (app === 'andotp') return this.tr('@importSelectAppExport').replace('{appName}', 'andOTP');
    if (app === 'otpauth') return this.tr('@importSelectAppExport').replace('{appName}', 'OTP Auth');
    return this.tr('选择 JSON 文件');
  }

  private runImportGuideAction(app: string): void {
    this.importGuideApp = '';
    if (app === 'ga') {
      this.importGoogleAuth();
      return;
    }
    this.importFromFile(app === 'ente');
  }

  // ---------- 本地备份（官方：开启后自动生成加密备份文件） ----------

  private async setBackupOn(v: boolean): Promise<void> {
    if (v && !this.backupPwdSet) {
      this.backupPwdInput = '';
      this.backupPwdOpen = true;
      return;
    }
    this.backupOn = v;
    if (this.store !== null) this.store.put(KEY_BACKUP_ON, v ? '1' : '0');
    this.refreshCurrentPage();
    if (v) await this.runBackup(false);
  }

  private async saveBackupPwd(): Promise<void> {
    const pwd: string = this.backupPwdInput;
    if (pwd.length < 8) {
      this.toast(this.tr('密码长度必须至少为 8 个字符。'));
      return;
    }
    this.backupPwdCache = pwd;
    this.backupPwdSet = true;
    this.backupOn = true;
    if (this.store !== null) {
      this.store.put(KEY_BACKUP_ON, '1');
      this.store.put(KEY_BACKUP_PWD, await Sealer.seal(pwd));
    }
    this.backupPwdOpen = false;
    this.refreshCurrentPage();
    await this.runBackup(false);
  }

  private async backupContent(): Promise<string> {
    if (this.bridge === null) return '';
    const lines: string[] = this.exportableUris();
    if (lines.length === 0) return '';
    const args: string = JSON.stringify({ password: this.backupPwdCache, plain: lines.join('\n') });
    const res: BridgeResult = await this.bridge.call('encryptExport', args, 180000);
    return res.ok ? res.payload : '';
  }

  private async runBackup(silent: boolean): Promise<void> {
    if (this.backupBusy) return;
    if (this.backupPwdCache.length === 0) {
      // 对齐官方：未设密码时直接弹出设置备份密码弹层
      this.backupOpenPwdSheet();
      return;
    }
    this.backupBusy = true;
    try {
      const content: string = await this.backupContent();
      if (content.length === 0) {
        if (!silent) this.toast(this.tr('没有可备份的条目'));
        return;
      }
      const dir: string = this.backupPath;
      try {
        fileIo.mkdirSync(dir);
      } catch (e) {
        // 目录已存在
      }
      const name: string = 'ente-auth-backup-' + this.stamp() + '.json';
      const path: string = dir + '/' + name;
      const f: fileIo.File = fileIo.openSync(path,
        fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE | fileIo.OpenMode.TRUNC);
      try {
        fileIo.writeSync(f.fd, content);
      } finally {
        fileIo.closeSync(f);
      }
      this.pruneBackups(dir);
      if (!silent) this.toast(this.tr('已创建备份！'));
    } catch (e) {
      if (!silent) this.toast(this.tr('备份失败'));
    } finally {
      this.backupBusy = false;
    }
  }

  private backupOpenPwdSheet(): void {
    this.backupPwdInput = this.backupPwdCache;
    this.backupPwdOpen = true;
  }

  private pruneBackups(dir: string): void {
    try {
      const list: string[] = fileIo.listFileSync(dir);
      if (list.length <= 5) return;
      for (let i = 0; i < list.length - 5; i++) {
        if (!list[i].endsWith('.json')) continue;
        try {
          fileIo.unlinkSync(dir + '/' + list[i]);
        } catch (e) {
          // 忽略单个文件失败
        }
      }
    } catch (e) {
      // 忽略
    }
  }

  private setHideCodes(v: boolean): void {
    this.hideCodes = v;
    this.revealedId = '';
    if (this.store !== null) this.store.put(KEY_HIDE_CODES, v ? '1' : '0');
  }

  private setLockDelay(v: number): void {
    this.lockDelay = v;
    if (this.store !== null) this.store.put(KEY_LOCK_DELAY, v.toString());
    this.refreshCurrentPage();
  }

  // 敏感操作前要求身份验证（与应用锁一致，官方同类行为）
  private async requireAuth(then: () => void): Promise<void> {
    if (!this.appLock) {
      then();
      return;
    }
    const ok: boolean = await Biometrics.verify(this.tr('请验证'));
    if (!ok) {
      return;
    }
    then();
  }

  // ---------- 视图 ----------

  // ---------- 顶栏（对齐官方 App：白底、侧边菜单、居中 wordmark、内联搜索） ----------

  @Builder
  barMenu() {
    Button({ type: ButtonType.Normal }) {
      SymbolGlyph($r('sys.symbol.line_3_horizontal'))
        .fontSize(22)
        .fontColor([this.textColor()])
    }
    .width(44)
    .height(44)
    .backgroundColor(Color.Transparent)
    .borderRadius(22)
    .attributeModifier(this.matBtnUltraThin)
    .onClick(() => {
      this.searchOpen = false;
      this.exitSelection();
      this.drawerOpen = true;
    })
  }

  @Builder
  barSearch() {
    Button({ type: ButtonType.Normal }) {
      SymbolGlyph($r('sys.symbol.magnifyingglass'))
        .fontSize(22)
        .fontColor([this.textColor()])
    }
    .width(44)
    .height(44)
    .backgroundColor(Color.Transparent)
    .borderRadius(22)
    .attributeModifier(this.matBtnUltraThin)
    .onClick(() => {
      this.searchOpen = true;
    })
  }

  @Builder
  barClose() {
    Button({ type: ButtonType.Normal }) {
      SymbolGlyph($r('sys.symbol.xmark'))
        .fontSize(20)
        .fontColor([this.textColor()])
    }
    .width(44)
    .height(44)
    .backgroundColor(Color.Transparent)
    .borderRadius(22)
    .onClick(() => {
      this.searchOpen = false;
      this.query = '';
    })
  }

  // 编辑顺序（排序）入口：位于搜索图标左侧
  @Builder
  barSort() {
    Button({ type: ButtonType.Normal }) {
      SymbolGlyph($r('sys.symbol.sort'))
        .fontSize(20)
        .fontColor([this.textColor()])
    }
    .width(44)
    .height(44)
    .backgroundColor(Color.Transparent)
    .borderRadius(22)
    .attributeModifier(this.matBtnUltraThin)
    .onClick(() => {
      // 多选状态下不打开排序面板，避免与多选操作层叠加
      if (this.selectionMode) return;
      this.fabOpen = false;
      this.searchOpen = false;
      this.sortOpen = true;
    })
  }

  @Builder
  appBarNormal() {
    Stack({ alignContent: Alignment.Center }) {
      Row() {
        // 顶部菜单固定左侧（对齐官方默认），不随握持手换边
        this.barMenu()
        Blank()
        Row() {
          this.barSort()
          this.barSearch()
        }
      }
      .width('100%')
      .height(56)

      Row() {
        Text('Auth')
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
      }
      .hitTestBehavior(HitTestMode.Transparent)
    }
    .width('100%')
    .padding({ top: this.topInset })
    .backgroundColor(this.bg())
  }

  @Builder
  appBarSearch() {
    Row() {
      this.barClose()
      TextInput({ text: this.query, placeholder: this.tr('搜索...') })
        .layoutWeight(1)
        .height(40)
        .fontSize(15)
        .backgroundColor(Color.Transparent)
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .onChange((v: string) => {
          this.query = v;
        })
      Row().width(8)
    }
    .width('100%')
    .height(56 + this.topInset)
    .padding({ top: this.topInset })
    .backgroundColor(this.bg())
  }

  // ---------- 码表卡片（对齐官方：圆角卡片 + 大号当前码 + Next code + 底部计时条） ----------

  private iconSlugOf(provider: string): string {
    const i: ProviderIcon | null = this.iconFor(provider);
    return i === null ? '' : i.slug;
  }

  // 与官方一致：深色主题下过暗的品牌色、浅色主题下过亮的品牌色改用主题文字色
  private iconHexOf(provider: string): string {
    const i: ProviderIcon | null = this.iconFor(provider);
    if (i === null || i.hex.length !== 6) return this.textColor();
    const r: number = parseInt(i.hex.substring(0, 2), 16);
    const g: number = parseInt(i.hex.substring(2, 4), 16);
    const b: number = parseInt(i.hex.substring(4, 6), 16);
    const lum: number = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    if (this.dark && lum < 0.12) return this.textColor();
    if (!this.dark && lum > 0.72) return this.textColor();
    return '#' + i.hex;
  }

  @Builder
  rowIcon(r: OtpRow, size: number) {
    Stack() {
      if (this.iconSlugOf(this.titleOf(r)).length > 0) {
        Image($rawfile('providers/icons/' + this.iconSlugOf(this.titleOf(r)) + '.svg'))
          .width(size)
          .height(size)
          .objectFit(ImageFit.Contain)
          .fillColor(this.iconHexOf(this.titleOf(r)))
      } else {
        Text(this.avatarLetterOf(this.titleOf(r)))
          .width(size)
          .height(size)
          .borderRadius(size / 2)
          .backgroundColor(this.avatarColorOf(this.titleOf(r)))
          .fontSize(Math.round(size * 0.6))
          .fontWeight(FontWeight.Medium)
          .fontColor('#FFFFFF')
          .textAlign(TextAlign.Center)
      }
    }
    .width(size)
    .height(size)
  }

  // 卡片内容（大图标模式图标在左，普通模式图标在右上）
  @Builder
  cardContent(r: OtpRow) {
    Row() {
      if (this.bigIcons) {
        this.rowIcon(r, this.compact ? 32 : 42)
      }
      Column() {
        Row() {
          if (this.selectionMode) {
            Stack() {
              if (this.isSelected(r.id)) {
                SymbolGlyph($r('sys.symbol.checkmark'))
                  .fontSize(11)
                  .fontColor([Color.White])
                  // 勾选时从略小处放大淡入，取消勾选时反向缩回
                  .transition(TransitionEffect.scale({ x: 0.4, y: 0.4 })
                    .combine(TransitionEffect.OPACITY)
                    .animation({ duration: 160, curve: Curve.EaseOut }))
              }
            }
            .width(20)
            .height(20)
            .borderRadius(10)
            .backgroundColor(this.isSelected(r.id) ? this.primary() : Color.Transparent)
            .border({ width: 1.5, color: this.primary() })
            .margin({ right: 8 })
            // 进入/退出多选时勾选圈缩放淡入淡出，勾选底色平滑过渡
            .transition(TransitionEffect.scale({ x: 0.6, y: 0.6 })
              .combine(TransitionEffect.OPACITY)
              .animation({ duration: 180, curve: Curve.EaseOut }))
            .animation({ duration: 160, curve: Curve.EaseOut })
          }
          Text(this.titleOf(r))
            .fontSize(this.compact ? 15 : 18)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.textColor())
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .layoutWeight(1)
          if (r.pinned) {
            Text(this.tr('置顶'))
              .fontSize(10)
              .fontColor(this.primary())
              .margin({ left: 6 })
          }
          if (r.broken) {
            Text(this.tr('出了点问题'))
              .fontSize(10)
              .fontColor('#F53434')
              .margin({ left: 6 })
          }
          if (!this.bigIcons) {
            Row() {
              this.rowIcon(r, 24)
            }
            .margin({ left: 8 })
          }
        }
        .width('100%')

        if (r.account.length > 0) {
          Text(r.account)
            .fontSize(this.compact ? 11 : 12)
            .fontColor(this.muted())
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .margin({ top: 2 })
        }
        if (r.note.length > 0 && !this.compact) {
          Text(r.note)
            .fontSize(12)
            .fontColor(this.faint())
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .margin({ top: 2 })
        }

        Row() {
          Text(this.displayCode(r))
            .fontSize(this.compact ? 14 : 24)
            .fontWeight(FontWeight.Bold)
            .fontColor(this.textColor())
            .letterSpacing(1)
            .layoutWeight(1)
          if (r.type !== 'hotp') {
            Column() {
              Text(this.tr('下一个'))
                .fontSize(this.compact ? 10 : 12)
                .fontColor(this.muted())
              Text(this.displayNextCode(r))
                .fontSize(this.compact ? 12 : 18)
                .fontColor(this.muted())
                .letterSpacing(1)
                .margin({ top: this.compact ? 0 : 2 })
            }
            .alignItems(HorizontalAlign.End)
            .onClick(() => {
              if (this.selectionMode) {
                this.toggleSelection(r);
                return;
              }
              this.copyNextCode(r);
            })
          }
        }
        .width('100%')
        .margin({ top: this.compact ? 4 : 14 })
        .alignItems(VerticalAlign.Bottom)
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)
      .margin({ left: this.bigIcons ? (this.compact ? 12 : 16) : 0 })
    }
    .width('100%')
    .alignItems(VerticalAlign.Top)
  }

  @Builder
  cardView(r: OtpRow) {
    Stack({ alignContent: Alignment.TopStart }) {
        Column() {
          this.cardContent(r)
        }
        .width('100%')
        .padding({
          left: 16,
          right: 16,
          top: (this.compact ? 8 : 12) + (this.compact ? 1 : 3),
          bottom: this.compact ? 10 : 14,
        })

        // 顶部计时条（官方：3vp / 紧凑 1vp，剩余 >40% 紫色，否则橙色）
        CodeBar({
          period: r.period,
          barHeight: this.compact ? 1 : 3,
          hotColor: this.primary(),
          coldColor: this.orange(),
          isHotp: r.type === 'hotp',
        })
      }
      .width('100%')
      .backgroundColor(this.isSelected(r.id)
        ? this.selectedBg()
        : (r.pinned ? this.pinnedBg() : this.card()))
      .borderRadius(8)
      .border({
        width: this.isSelected(r.id) ? 1.5 : 0,
        color: this.primary(),
      })
      .clip(true)
      .shadow(r.pinned
        ? { radius: 8, color: '#14000000', offsetX: 0, offsetY: 2 }
        : { radius: 0, color: '#00000000', offsetX: 0, offsetY: 0 })
      .animation({ duration: 200, curve: Curve.EaseOut })
      .onClick(() => {
        if (this.selectionMode) {
          this.toggleSelection(r);
          return;
        }
        this.copyCode(r);
      })
      .gesture(GestureGroup(GestureMode.Exclusive,
        TapGesture({ count: 2 }).onAction(() => {
          if (!this.hideCodes || this.selectionMode) return;
          this.revealedId = this.revealedId === r.id ? '' : r.id;
        }),
        LongPressGesture({ repeat: false }).onAction(() => {
          this.enterSelection(r);
        })))
  }

  // 单列列表项
  @Builder
  codeCard(r: OtpRow) {
    ListItem() {
      this.cardView(r)
    }
    .margin({ bottom: this.compact ? 4 : 8 })
  }

  // 多列网格项（横屏/平板）
  @Builder
  gridCard(r: OtpRow) {
    GridItem() {
      this.cardView(r)
    }
  }

  // 悬浮按钮：官方 SpeedDial 展开（扫码 / 手动输入），菜单从 FAB 圆心放大钻出，反向缩回
  @Builder
  fab() {
    Column() {
      Column() {
        Row() {
          if (this.leftMode) {
            this.fabChild($r('sys.symbol.qrcode'), '扫描二维码', () => {
              this.fabOpen = false;
              this.scan();
            })
          } else {
            Text(this.tr('扫描二维码'))
              .fontSize(12)
              .fontColor(this.textColor())
              .backgroundColor(this.chipBg())
              .padding({ left: 10, right: 10, top: 6, bottom: 6 })
              .borderRadius(8)
              .margin({ right: 10 })
            this.fabChild($r('sys.symbol.qrcode'), '', () => {
              this.fabOpen = false;
              this.scan();
            })
          }
        }
        .margin({ bottom: 10 })
        Row() {
          if (this.leftMode) {
            this.fabChild($r('sys.symbol.keyboard'), '手动输入详细信息', () => {
              this.fabOpen = false;
              this.openAdd();
            })
          } else {
            Text(this.tr('手动输入详细信息'))
              .fontSize(12)
              .fontColor(this.textColor())
              .backgroundColor(this.chipBg())
              .padding({ left: 10, right: 10, top: 6, bottom: 6 })
              .borderRadius(8)
              .margin({ right: 10 })
            this.fabChild($r('sys.symbol.keyboard'), '', () => {
              this.fabOpen = false;
              this.openAdd();
            })
          }
        }
      }
      .width('100%')
      // 高度恒定，不做裁剪：菜单整体从 + 按钮圆心处放大“钻”出来，避免出现水平分割线
      .height(108)
      // 与 FAB 留出 12vp 间隙，避免展开后方形按钮贴着 + 按钮
      .margin({ bottom: 12 })
      .padding({
        // FAB 直径 56、展开项直径 44：偏移 (56-44)/2 = 6，保证两者圆心在同一条竖线上
        left: this.leftMode ? 6 : 0,
        right: this.leftMode ? 0 : 6,
      })
      .alignItems(this.leftMode ? HorizontalAlign.Start : HorizontalAlign.End)
      .justifyContent(FlexAlign.End)
      // 动画原点固定在 + 按钮中心：容器底边距 FAB 顶边 12vp，再向下 28vp 即 FAB 圆心
      .scale({
        x: this.fabOpen ? 1 : 0.18,
        y: this.fabOpen ? 1 : 0.18,
        centerX: this.leftMode ? 28 : Math.max(0, this.fabMenuW - 28),
        centerY: 148,
      })
      .opacity(this.fabOpen ? 1 : 0)
      // 收起后不参与触摸，避免透明菜单挡住列表点击
      .hitTestBehavior(this.fabOpen ? HitTestMode.Default : HitTestMode.None)
      .onAreaChange((oldV: Area, newV: Area) => {
        const w: number = Number(newV.width);
        if (w > 0 && Math.abs(w - this.fabMenuW) > 0.5) {
          this.fabMenuW = w;
        }
      })
      .animation({ duration: 260, curve: Curve.FastOutSlowIn })

      Button({ type: ButtonType.Circle }) {
        // + 号旋转 45° 变成 ×，展开/收起时都有连续旋转动画
        SymbolGlyph($r('sys.symbol.plus'))
          .fontSize(24)
          .fontColor([this.fabIcon()])
          .rotate({ angle: this.fabOpen ? 45 : 0, centerX: '50%', centerY: '50%' })
          .animation({ duration: 260, curve: Curve.FastOutSlowIn })
      }
      .width(56)
      .height(56)
      .backgroundColor(this.fabBg())
      .shadow({ radius: 12, color: '#33000000', offsetX: 0, offsetY: 4 })
      .attributeModifier(this.matBtnThin)
      .onClick(() => {
        this.fabOpen = !this.fabOpen;
      })
    }
    // 整体（+ 与展开菜单）作为一个横向位移的载体：换手时先滑出屏幕，再换边滑入
    .translate({ x: this.fabShift })
    .alignItems(this.leftMode ? HorizontalAlign.Start : HorizontalAlign.End)
    .margin({
      // 额外避让横屏时的摄像头挖孔/系统栏，保证展开菜单不与挖孔交叉
      left: this.leftMode ? 20 + this.safeL : 0,
      right: this.leftMode ? 0 : 20 + this.safeR,
      bottom: 28,
    })
  }

  @Builder
  fabChild(icon: Resource, label: string, tap: () => void) {
    Row() {
      if (this.leftMode) {
        Button({ type: ButtonType.Normal }) {
          SymbolGlyph(icon)
            .fontSize(20)
            .fontColor([this.fabIcon()])
        }
        .width(44)
        .height(44)
        .borderRadius(14)
        .backgroundColor(this.fabBg())
        .attributeModifier(this.matBtnFabChild)
        .onClick(tap)
        Text(this.tr(label))
          .fontSize(12)
          .fontColor(this.textColor())
          .backgroundColor(this.chipBg())
          .padding({ left: 10, right: 10, top: 6, bottom: 6 })
          .borderRadius(8)
          .margin({ left: 10 })
      } else {
        Button({ type: ButtonType.Normal }) {
          SymbolGlyph(icon)
            .fontSize(20)
            .fontColor([this.fabIcon()])
        }
        .width(44)
        .height(44)
        .borderRadius(14)
        .backgroundColor(this.fabBg())
        .attributeModifier(this.matBtnFabChild)
        .onClick(tap)
      }
    }
  }

  // 抽屉覆盖层：常驻挂载，用位移/透明度驱动，保证关闭与打开一样有过渡动画
  @Builder
  drawerLayer() {
    Column() {
      Column()
        .width('100%')
        .height('100%')
        .backgroundColor('#88000000')
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
        .opacity(this.drawerOpen ? 1 : 0)
        .animation({ duration: 200, curve: Curve.EaseOut })
        // 收起时遮罩不参与命中测试，避免挡住首页的点击
        .hitTestBehavior(this.drawerOpen ? HitTestMode.Default : HitTestMode.None)
        .onClick(() => {
          this.drawerOpen = false;
        })
      Column() {
        this.drawer()
      }
      .width(this.drawerWidth())
      .height('100%')
      // 抽屉固定从左侧滑出（Navigation 已按挖孔内缩，这里从父容器 0 起点开始）
      .position({ x: 0, y: 0 })
      .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      .translate({ x: this.drawerOpen ? 0 : -this.drawerWidth() - 20 })
      .animation({ duration: 240, curve: Curve.FastOutSlowIn })
      .hitTestBehavior(this.drawerOpen ? HitTestMode.Default : HitTestMode.None)
    }
    .width('100%')
    .height('100%')
    // 收起时整层不参与点击，避免透明遮罩挡住首页
    .hitTestBehavior(this.drawerOpen ? HitTestMode.Default : HitTestMode.None)
  }

  // 首页标签分组筛选（对齐官方 TagChip：All + 各标签，左对齐横向滚动）
  @Builder
  tagFilterBar() {
    List({ space: 8 }) {
      ListItem() {
        this.tagChip('')
      }
      ForEach(this.allTags(), (t: string) => {
        ListItem() {
          this.tagChip(t)
        }
      }, (t: string) => t)
    }
    .listDirection(Axis.Horizontal)
    .alignListItem(ListItemAlign.Center)
    .scrollBar(BarState.Off)
    .width('100%')
    .height(48)
    .padding({ left: 16, right: 16, top: 2, bottom: 2 })
  }

  @Builder
  tagChip(value: string) {
    Row() {
      // 文案在 builder 内取词，切换语言时才能随 localeRev 刷新
      Text(value.length === 0 ? this.tr('全部') : value)
        .fontSize(13)
        .fontColor(this.activeTag() === value ? '#FFFFFF' : this.textColor())
        .maxLines(1)
        .height('100%')
        .padding({ left: 16, right: this.activeTag() === value && value.length > 0 ? 0 : 16 })
        .onClick(() => {
          this.setTagFilter(value);
        })
      // 选中自定义标签后展示「更多」，可编辑/删除（对齐官方 TagChip menu）
      if (this.activeTag() === value && value.length > 0) {
        Row({ space: 2 }) {
          Circle().width(3.5).height(3.5).fill('#FFFFFF')
          Circle().width(3.5).height(3.5).fill('#FFFFFF')
          Circle().width(3.5).height(3.5).fill('#FFFFFF')
        }
        .width(48)
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .onClick(() => {
          this.openTagMenu(value);
        })
      }
    }
    .height(40)
    .borderRadius(24)
    .backgroundColor(this.activeTag() === value ? this.primary() : this.card())
    .clip(true)
  }

  // 选中标签后的操作（对齐官方：标题 + 关闭按钮 + 白卡操作行）
  @Builder
  tagMenuDialog() {
    Column() {
      Row() {
        Text(this.tagMenuTag)
          .fontSize(17)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Stack() {
          Circle().width(36).height(36).fill(this.elevated())
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(15)
            .fontColor([this.textColor()])
        }
        .width(36)
        .height(36)
        .onClick(() => {
          this.tagMenuOpen = false;
        })
      }
      .width('100%')

      Column() {
        this.tagMenuItem($r('sys.symbol.pencil_line'), false)
        Divider()
          .color(this.dark ? '#2C2C2E' : '#EDEDED')
          .strokeWidth(1)
          .margin({ left: 56 })
        this.tagMenuItem($r('sys.symbol.trash'), true)
      }
      .width('100%')
      .backgroundColor(this.elevated())
      .borderRadius(20)
      .margin({ top: 16 })
      .clip(true)
    }
    .width('88%')
    .constraintSize({ maxWidth: 420 })
    .padding(16)
    .backgroundColor(this.chipBg())
    .borderRadius(24)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .onClick(() => {
    })
  }

  @Builder
  tagMenuItem(icon: Resource, danger: boolean) {
    Row({ space: 16 }) {
      SymbolGlyph(icon)
        .fontSize(20)
        .fontColor([danger ? this.dangerText() : this.muted()])
      // 文案在 builder 内取词，切换语言时才能随 localeRev 刷新
      Text(danger ? this.tr('删除') : this.tr('编辑'))
        .fontSize(15)
        .fontColor(danger ? this.dangerText() : this.textColor())
    }
    .width('100%')
    .height(56)
    .padding({ left: 16, right: 16 })
    .onClick(() => {
      if (danger) {
        this.tagMenuOpen = false;
        this.tagDeleteOpen = true;
      } else {
        this.openTagEdit();
      }
    })
  }

  @Builder
  tagEditDialog() {
    Column() {
      Text(this.tr('编辑标签'))
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.textColor())
        .width('100%')
      TextInput({ text: this.tagEditText, placeholder: this.tr('标签') })
        .width('100%')
        .height(42)
        .fontSize(14)
        .backgroundColor(this.inputBg())
        .borderRadius(8)
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .maxLength(100)
        .margin({ top: 12 })
        .onChange((v: string) => {
          this.tagEditText = v;
        })
      Row() {
        Button(this.tr('取消'))
          .height(42)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.tagEditOpen = false;
          })
        Button(this.tr('保存'))
          .height(42)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.primary())
          .fontColor('#FFFFFF')
          .onClick(() => {
            this.saveTagEdit();
          })
      }
      .width('100%')
      .margin({ top: 16 })
    }
    .width('86%')
    .constraintSize({ maxWidth: 420 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .onClick(() => {
    })
  }

  @Builder
  tagDeleteDialog() {
    Column() {
      Text(this.tr('要删除标签吗？'))
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('您确定要删除此标签吗？此操作是不可逆的。'))
        .fontSize(13)
        .fontColor(this.muted())
        .width('100%')
        .margin({ top: 8 })
      Row() {
        Button(this.tr('取消'))
          .height(42)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.tagDeleteOpen = false;
          })
        Button(this.tr('删除'))
          .height(42)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.dangerBg())
          .fontColor(this.dangerText())
          .onClick(() => {
            this.deleteTag();
          })
      }
      .width('100%')
      .margin({ top: 16 })
    }
    .width('86%')
    .constraintSize({ maxWidth: 420 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .onClick(() => {
    })
  }

  @Builder
  nativeBody() {
    Stack({ alignContent: Alignment.BottomEnd }) {
      // 旋转适配：横屏/平板下内容列限宽 720vp 并水平居中，避免列表卡片被拉得过宽
      Row() {
        Column() {
          if (this.searchOpen) {
          this.appBarSearch()
        } else {
          this.appBarNormal()
        }
        if (this.notice.length > 0) {
          Text(this.notice)
            .fontSize(12)
            .fontColor('#8A5A00')
            .backgroundColor('#FFF4E5')
            .width('100%')
            .padding({ left: 16, right: 16, top: 8, bottom: 8 })
        }

        if (this.hasCodes()) {
          this.tagFilterBar()
        }

        if (this.visibleRows().length === 0) {
          Column() {
            SymbolGlyph($r('sys.symbol.key_shield'))
              .fontSize(40)
              .fontColor([this.faint()])
            Text(this.tr('这里暂时没有任何内容。点按 + 添加代码，或打开回收站恢复代码。'))
              .fontSize(14)
              .fontColor(this.muted())
              .textAlign(TextAlign.Center)
              .margin({ top: 12, left: 32, right: 32 })
              .lineHeight(22)
          }
          .layoutWeight(1)
          .justifyContent(FlexAlign.Center)
        } else {
          if (this.gridColumns() > 1) {
            // 横屏/平板：一行多个验证码（对齐官方横屏布局）
            Grid() {
              ForEach(this.visibleRows(), (r: OtpRow) => {
                this.gridCard(r);
              }, (r: OtpRow) => r.id + ':' + r.step)
            }
            .columnsTemplate(this.columnsTemplate())
            .columnsGap(8)
            .rowsGap(this.compact ? 4 : 8)
            .layoutWeight(1)
            .width('100%')
            .padding({ left: 16, right: 16, top: 8, bottom: 88 })
            .scrollBar(BarState.Off)
            .edgeEffect(EdgeEffect.Spring)
          } else {
            List() {
              ForEach(this.visibleRows(), (r: OtpRow) => {
                this.codeCard(r);
              }, (r: OtpRow) => r.id + ':' + r.step)
              ListItem() {
                Row().width('100%').height(88)
              }
            }
            .layoutWeight(1)
            .width('100%')
            .padding({ left: 16, right: 16, top: 8 })
            .scrollBar(BarState.Off)
            .edgeEffect(EdgeEffect.Spring)
          }
        }
        }
        .width('100%')
        .constraintSize({ maxWidth: this.gridColumns() >= 3 ? 1024 : 720 })
        .height('100%')
        .backgroundColor(this.bg())
      }
      .width('100%')
      .height('100%')
      .justifyContent(FlexAlign.Center)
      .backgroundColor(this.bg())

      if (!this.selectionMode) {
        this.fab()
      }

      // 侧边抽屉挂在导航内容层：常驻挂载以支持关闭动画；点击菜单项入栈后抽屉保留
      this.drawerLayer()

      if (this.tagMenuOpen) {
        Column() {
          this.tagMenuDialog()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor('#66000000')
        .onClick(() => {
          this.tagMenuOpen = false;
        })
      }

      if (this.tagEditOpen) {
        Column() {
          this.tagEditDialog()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor('#66000000')
        .onClick(() => {
          this.tagEditOpen = false;
        })
      }

      if (this.tagDeleteOpen) {
        Column() {
          this.tagDeleteDialog()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor('#66000000')
        .onClick(() => {
          this.tagDeleteOpen = false;
        })
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor(this.bg())
  }

  @Builder
  formLabel(label: string, required: boolean) {
    Row() {
      Text(this.tr(label))
        .fontSize(14)
        .fontColor(this.textColor())
      if (required) {
        Text(' *')
          .fontSize(14)
          .fontColor('#F53434')
      }
    }
    .width('100%')
    .margin({ top: 18, bottom: 8 })
  }

  @Builder
  sheet() {
    Column() {
      // 对齐官方「Enter account details」：Issuer / Secret / Account / Notes / Tags / Advanced
      this.formLabel('发行方', false)
      TextInput({ text: this.formIssuer, placeholder: this.tr('例如 GitHub') })
        .width('100%')
        .height(48)
        .fontSize(16)
        .fontColor(this.textColor())
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .backgroundColor(this.card())
        .borderRadius(12)
        .padding({ left: 14, right: 14 })
        .onChange((v: string) => {
          this.formIssuer = v;
        })

      this.formLabel('密钥', true)
      Row() {
        TextInput({ text: this.formSecret, placeholder: 'JBSWY3DPEHPK3PXP' })
          .layoutWeight(1)
          .height(48)
          .fontSize(16)
          .fontColor(this.textColor())
          .placeholderColor(this.faint())
          .caretColor(this.primary())
          .backgroundColor(Color.Transparent)
          .padding({ left: 14, right: 4 })
          .type(this.secretVisible ? InputType.Normal : InputType.Password)
          .showPasswordIcon(false)
          .onChange((v: string) => {
            this.formSecret = v;
          })
        Button({ type: ButtonType.Circle }) {
          if (this.secretVisible) {
            SymbolGlyph($r('sys.symbol.eye_slash'))
              .fontSize(18)
              .fontColor([this.muted()])
          } else {
            SymbolGlyph($r('sys.symbol.eye'))
              .fontSize(18)
              .fontColor([this.muted()])
          }
        }
        .width(40)
        .height(40)
        .margin({ right: 4 })
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.secretVisible = !this.secretVisible;
        })
      }
      .width('100%')
      .height(48)
      .backgroundColor(this.card())
      .borderRadius(12)

      this.formLabel('账户', false)
      TextInput({ text: this.formAccount, placeholder: this.tr('例如 user@example.com') })
        .width('100%')
        .height(48)
        .fontSize(16)
        .fontColor(this.textColor())
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .backgroundColor(this.card())
        .borderRadius(12)
        .padding({ left: 14, right: 14 })
        .onChange((v: string) => {
          this.formAccount = v;
        })

      this.formLabel('备注', false)
      TextArea({ text: this.formNote, placeholder: this.tr('可选') })
        .width('100%')
        .height(100)
        .fontSize(16)
        .fontColor(this.textColor())
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .backgroundColor(this.card())
        .borderRadius(12)
        .padding(14)
        .onChange((v: string) => {
          this.formNote = v;
        })

      this.formLabel('标签', false)
      // 对齐官方：列出全部已有标签可直接勾选，末尾为「添加标签」
      Flex({ wrap: FlexWrap.Wrap }) {
        ForEach(this.formTagOptions(), (t: string) => {
          Button({ type: ButtonType.Capsule }) {
            Text(t)
              .fontSize(13)
              .fontColor(this.formTags.indexOf(t) >= 0 ? '#FFFFFF' : this.textColor())
          }
          .height(36)
          .padding({ left: 14, right: 14 })
          .backgroundColor(this.formTags.indexOf(t) >= 0 ? this.primary() : this.chipBg())
          .margin({ right: 8, bottom: 8 })
          .onClick(() => {
            this.toggleFormTag(t);
          })
        }, (t: string) => 'ftag:' + t)
        Button({ type: ButtonType.Capsule }) {
          Row() {
            SymbolGlyph($r('sys.symbol.plus'))
              .fontSize(12)
              .fontColor([this.muted()])
            Text(this.tr('添加标签'))
              .fontSize(13)
              .fontColor(this.textColor())
              .margin({ left: 5 })
          }
        }
        .height(36)
        .padding({ left: 12, right: 14 })
        .backgroundColor(this.chipBg())
        .margin({ bottom: 8 })
        .onClick(() => {
          this.tagInput = '';
          this.tagForForm = true;
        })
      }
      .width('100%')

      // 高级：算法 / 类型 / 周期 / 位数（默认收起，对齐官方）
      Column() {
        Row() {
          Text(this.tr('高级'))
            .fontSize(16)
            .fontColor(this.textColor())
            .layoutWeight(1)
          SymbolGlyph($r('sys.symbol.chevron_down'))
            .fontSize(14)
            .fontColor([this.muted()])
            .rotate({ angle: this.advancedOpen ? 180 : 0 })
            .animation({ duration: 220, curve: Curve.FastOutSlowIn })
        }
        .width('100%')
        .height(56)
        .padding({ left: 16, right: 16 })
        .onClick(() => {
          animateTo({ duration: 240, curve: Curve.FastOutSlowIn }, () => {
            this.advancedOpen = !this.advancedOpen;
          });
        })

        if (this.advancedOpen) {
          Column() {
            Divider().color(this.divider())
            Row() {
              Text(this.tr('算法'))
                .fontSize(16)
                .fontColor(this.textColor())
                .layoutWeight(1)
              Text(this.algName())
                .fontSize(14)
                .fontColor(this.muted())
              SymbolGlyph($r('sys.symbol.chevron_right'))
                .fontSize(14)
                .fontColor([this.faint()])
                .margin({ left: 6 })
            }
            .width('100%')
            .height(56)
            .padding({ left: 16, right: 16 })
            .onClick(() => {
              this.pickKind = 0;
              this.pickOpen = true;
            })

            Divider().color(this.divider())
            Row() {
              Text(this.tr('类型'))
                .fontSize(16)
                .fontColor(this.textColor())
                .layoutWeight(1)
              Text(this.typeName())
                .fontSize(14)
                .fontColor(this.muted())
              SymbolGlyph($r('sys.symbol.chevron_right'))
                .fontSize(14)
                .fontColor([this.faint()])
                .margin({ left: 6 })
            }
            .width('100%')
            .height(56)
            .padding({ left: 16, right: 16 })
            .onClick(() => {
              this.pickKind = 1;
              this.pickOpen = true;
            })

            Divider().color(this.divider())
          Row() {
            Column() {
              Text(this.tr('周期'))
                .fontSize(14)
                .fontColor(this.textColor())
                .width('100%')
                .margin({ bottom: 8 })
              TextInput({ text: this.formPeriod })
                .type(InputType.Number)
                .width('100%')
                .height(48)
                .fontSize(16)
                .fontColor(this.textColor())
                .caretColor(this.primary())
                .backgroundColor(this.chipBg())
                .borderRadius(12)
                .padding({ left: 14, right: 14 })
                .onChange((v: string) => {
                  this.formPeriod = v;
                })
            }
            .layoutWeight(1)
            .alignItems(HorizontalAlign.Start)

            Column() {
              Text(this.tr('数字'))
                .fontSize(14)
                .fontColor(this.textColor())
                .width('100%')
                .margin({ bottom: 8 })
              TextInput({ text: this.formDigits })
                .type(InputType.Number)
                .width('100%')
                .height(48)
                .fontSize(16)
                .fontColor(this.textColor())
                .caretColor(this.primary())
                .backgroundColor(this.chipBg())
                .borderRadius(12)
                .padding({ left: 14, right: 14 })
                .onChange((v: string) => {
                  this.formDigits = v;
                })
            }
            .layoutWeight(1)
            .alignItems(HorizontalAlign.Start)
            .margin({ left: 12 })
          }
          .width('100%')
          .padding({ left: 16, right: 16, top: 16, bottom: 16 })
          }
          .width('100%')
          .transition(TransitionEffect.OPACITY.animation({ duration: 200, curve: Curve.FastOutSlowIn })
            .combine(TransitionEffect.translate({ y: -8 })
              .animation({ duration: 220, curve: Curve.FastOutSlowIn })))
        }
      }
      .width('100%')
      .backgroundColor(this.card())
      .borderRadius(12)
      .margin({ top: 18 })

      Button(this.tr('保存'))
        .width('100%')
        .height(48)
        .fontSize(16)
        .margin({ top: 24, bottom: 12 })
        .backgroundColor(this.primary())
        .fontColor('#FFFFFF')
        .borderRadius(12)
        .onClick(() => {
          this.saveForm();
        })
    }
    .width('100%')
    .padding(20)
    .backgroundColor(this.bg())
  }

  // 手动添加页内的「创建新标签」弹层（对齐官方文案）
  @Builder
  formTagDialog() {
    Column() {
      Text(this.tr('创建新标签'))
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.textColor())
        .width('100%')
      TextInput({ text: this.tagInput, placeholder: this.tr('标签') })
        .width('100%')
        .height(42)
        .maxLength(100)
        .fontSize(14)
        .backgroundColor(this.inputBg())
        .borderRadius(8)
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .margin({ top: 12 })
        .onChange((v: string) => {
          this.tagInput = v;
        })
      Row() {
        Button(this.tr('取消'))
          .height(42)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.tagForForm = false;
            this.tagInput = '';
          })
        Button(this.tr('创建'))
          .height(42)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.primary())
          .fontColor('#FFFFFF')
          .onClick(() => {
            this.applyFormTag();
          })
      }
      .width('100%')
      .margin({ top: 16 })
    }
    .width('86%')
    .constraintSize({ maxWidth: 420 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .onClick(() => {
    })
  }

  // 算法 / 类型选择弹层（对齐官方单选卡片）
  @Builder
  pickDialog() {
    Column() {
      Row() {
        Text(this.pickKind === 0 ? this.tr('算法') : this.tr('类型'))
          .fontSize(18)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(14)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(this.bg())
        .onClick(() => {
          this.pickOpen = false;
        })
      }
      .width('100%')
      .padding({ left: 16, right: 16, top: 16, bottom: 12 })

      Column() {
        ForEach(this.pickKind === 0 ? ['SHA1', 'SHA256', 'SHA512'] : ['TOTP', 'HOTP', 'STEAM'],
          (label: string, idx: number) => {
            Column() {
              Row() {
                Text(label)
                  .fontSize(16)
                  .fontColor(this.textColor())
                  .layoutWeight(1)
                Stack() {
                  Circle()
                    .width(20)
                    .height(20)
                    .fill(Color.Transparent)
                    .stroke(this.isPicked(idx) ? this.primary() : '#BDBDBD')
                    .strokeWidth(1.5)
                  if (this.isPicked(idx)) {
                    Circle()
                      .width(10)
                      .height(10)
                      .fill(this.primary())
                  }
                }
                .width(20)
                .height(20)
              }
              .width('100%')
              .height(56)
              .padding({ left: 16, right: 16 })
              .onClick(() => {
                this.applyPick(this.pickKind, idx);
              })
              if (idx < 2) {
                Divider()
                  .color(this.divider())
                  .margin({ left: 16, right: 16 })
              }
            }
            .width('100%')
          },
          (label: string) => 'pick:' + label)
      }
      .width('100%')
      .backgroundColor(this.bg())
      .borderRadius(16)
    }
    .width('86%')
    .constraintSize({ maxWidth: 420 })
    .padding({ left: 8, right: 8, top: 4, bottom: 8 })
    .backgroundColor(this.card())
    .borderRadius(20)
    .onClick(() => {
    })
  }

  @Builder
  formPage() {
    NavDestination() {
      Stack() {
        Column() {
          this.pageHeader('输入账户详细信息')
          Scroll() {
          Column() {
            this.sheet()
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          }
          .layoutWeight(1)
          .align(Alignment.Top)
          .scrollBar(BarState.Off)
        }
        .width('100%')
        .height('100%')
        .backgroundColor(this.bg())

        if (this.tagForForm) {
          Column() {
            this.formTagDialog()
          }
          .width('100%')
          .height('100%')
          .justifyContent(FlexAlign.Center)
          .backgroundColor('#66000000')
          .onClick(() => {
            this.tagForForm = false;
            this.tagInput = '';
          })
        }

        if (this.pickOpen) {
          Column() {
            this.pickDialog()
          }
          .width('100%')
          .height('100%')
          .justifyContent(FlexAlign.Center)
          .backgroundColor('#66000000')
          .onClick(() => {
            this.pickOpen = false;
          })
        }
      }
      .width('100%')
      .height('100%')
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  menuRow(title: string, tap: () => void) {
    Button(this.tr(title))
      .width('100%')
      .height(44)
      .backgroundColor(this.inputBg())
      .fontColor(this.textColor())
      .fontSize(14)
      .margin({ bottom: 8 })
      .onClick(tap)
  }

  @Builder
  menuRowDanger(title: string, tap: () => void) {
    Button(this.tr(title))
      .width('100%')
      .height(44)
      .backgroundColor(this.dangerBg())
      .fontColor(this.dangerText())
      .fontSize(14)
      .margin({ bottom: 8 })
      .onClick(tap)
  }

  @Builder
  menuCard() {
    Column() {
      Text(this.menuTitle)
        .fontSize(14)
        .fontColor(this.muted())
        .margin({ bottom: 10 })
      ForEach(this.menuRows(), (r: OtpRow) => {
        Column() {
          this.menuRow('编辑', () => {
            this.menuId = '';
            this.openEdit(r);
          })
          this.menuRow('二维码', () => {
            this.openQr(r);
          })
          this.menuRow('分享', () => {
            this.menuId = '';
            this.shareRow(r);
          })
          this.menuRow('备注', () => {
            this.openNote(r);
          })
          this.menuRow(r.pinned ? '取消置顶' : '置顶', () => {
            this.togglePin(r);
          })
          this.menuRow(r.trashed ? '恢复' : '回收站', () => {
            this.toggleTrash(r);
          })
          this.menuRowDanger('删除', () => {
            this.menuConfirm = true;
          })
        }
        .width('100%')
      }, (r: OtpRow) => r.id)
      Button(this.tr('取消'))
        .width('100%')
        .height(44)
        .backgroundColor(this.inputBg())
        .fontColor(this.muted())
        .fontSize(14)
        .onClick(() => {
          this.menuId = '';
        })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 })
      .combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 独立浮层：避免在同一 @Builder 内切换分支导致按钮命中失效
  @Builder
  confirmCard() {
    Column() {
      Text(this.tr('要删除代码吗？'))
        .fontSize(15)
        .fontColor(this.dangerText())
        .margin({ bottom: 6 })
      Text(this.tr('您确定要删除此代码吗？此操作不可逆。'))
        .fontSize(12)
        .fontColor(this.muted())
        .margin({ bottom: 14 })
      Row() {
        Button(this.tr('取消'))
          .height(40)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.menuConfirm = false;
            this.menuId = '';
          })
        Button(this.tr('删除'))
          .height(40)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor('#D32F2F')
          .onClick(() => {
            const id: string = this.menuId;
            this.menuConfirm = false;
            this.menuId = '';
            this.removeRowById(id);
          })
      }
      .width('100%')
    }
    .width('82%')
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.OPACITY
      .combine(TransitionEffect.scale({ x: 0.92, y: 0.92 }))
      .animation({ duration: 200, curve: Curve.Friction }))
  }

  private menuRows(): OtpRow[] {
    const out: OtpRow[] = [];
    for (const r of this.rows) {
      if (r.id === this.menuId) out.push(r);
    }
    return out;
  }

  // ---------- 多选（对齐官方：长按进入，底部操作项随选择结果变化） ----------

  private isSelected(id: string): boolean {
    return this.selectedIds.indexOf(id) >= 0;
  }

  private selectedRows(): OtpRow[] {
    const out: OtpRow[] = [];
    for (const r of this.rows) {
      if (this.isSelected(r.id)) out.push(r);
    }
    return out;
  }

  private enterSelection(r: OtpRow): void {
    this.menuId = '';
    this.menuConfirm = false;
    this.fabOpen = false;
    this.selectionMode = true;
    if (!this.isSelected(r.id)) {
      const next: string[] = this.selectedIds.slice();
      next.push(r.id);
      this.selectedIds = next;
    }
  }

  private toggleSelection(r: OtpRow): void {
    const next: string[] = [];
    let removed: boolean = false;
    for (const id of this.selectedIds) {
      if (id === r.id) {
        removed = true;
      } else {
        next.push(id);
      }
    }
    if (!removed) next.push(r.id);
    this.selectedIds = next;
    if (next.length === 0) {
      this.selectionMode = false;
    }
  }

  private exitSelection(): void {
    this.selectionMode = false;
    this.selectedIds = [];
    this.tagOpen = false;
    this.tagInput = '';
  }

  // 全选：当前筛选下可见的条目（不含回收站里的）
  private selectAllVisible(): void {
    const ids: string[] = [];
    for (const r of this.visibleRows()) {
      if (!r.trashed && !r.broken) ids.push(r.id);
    }
    this.selectedIds = ids;
    if (ids.length === 0) this.selectionMode = false;
  }

  private selectedAllTrashed(): boolean {
    const list: OtpRow[] = this.selectedRows();
    if (list.length === 0) return false;
    for (const r of list) {
      if (!r.trashed) return false;
    }
    return true;
  }

  private selectedAllPinned(): boolean {
    const list: OtpRow[] = this.selectedRows();
    if (list.length === 0) return false;
    for (const r of list) {
      if (!r.pinned) return false;
    }
    return true;
  }

  private async pinSelected(): Promise<void> {
    if (this.bridge === null) return;
    const target: boolean = !this.selectedAllPinned();
    const list: OtpRow[] = this.selectedRows();
    let done: number = 0;
    for (const r of list) {
      const res: BridgeResult = await this.bridge.call('setPinned',
        '{"id":' + JSON.stringify(r.id) + ',"pinned":' + (target ? 'true' : 'false') + '}');
      if (res.ok) done++;
    }
    this.exitSelection();
    this.toast(this.icuPlural(target ? '@pinnedCount' : '@unpinnedCount', done));
    this.requestList(true);
  }

  private async trashSelected(): Promise<void> {
    if (this.bridge === null) return;
    const restoring: boolean = this.selectedAllTrashed();
    const list: OtpRow[] = this.selectedRows();
    let done: number = 0;
    for (const r of list) {
      const res: BridgeResult = await this.bridge.call('setTrashed',
        '{"id":' + JSON.stringify(r.id) + ',"trashed":' + (restoring ? 'false' : 'true') + '}');
      if (res.ok) done++;
    }
    this.exitSelection();
    this.toast(restoring
      ? this.icuPlural('@restoredItems', done)
      : this.tr('已移至回收站'));
    this.requestList(true);
  }

  private async deleteSelectedForever(): Promise<void> {
    if (this.bridge === null) return;
    const list: OtpRow[] = this.selectedRows();
    let done: number = 0;
    for (const r of list) {
      const res: BridgeResult = await this.bridge.call('remove', '{"id":' + JSON.stringify(r.id) + '}');
      if (res.ok) done++;
    }
    const keep: OtpRow[] = [];
    for (const x of this.rows) {
      if (!this.isSelected(x.id)) keep.push(x);
    }
    this.rows = keep;
    this.exitSelection();
    this.saveCache();
    this.requestList(true);
  }

  // 选中条目里出现过的标签（添加标签弹窗展示）
  private tagOptions(): string[] {
    const out: string[] = [];
    for (const r of this.selectedRows()) {
      for (const t of r.tags) {
        if (out.indexOf(t) < 0) out.push(t);
      }
    }
    return out;
  }

  private async applyTags(): Promise<void> {
    if (this.bridge === null) return;
    const base: string[] = this.tagOptions();
    const typed: string = this.tagInput.trim();
    const extra: string[] = [];
    for (const t of base) extra.push(t);
    if (typed.length > 0 && extra.indexOf(typed) < 0) extra.push(typed);
    if (extra.length === 0) {
      // 与官方一致：未输入标签名时不提交，也不额外提示
      return;
    }
    const list: OtpRow[] = this.selectedRows();
    for (const r of list) {
      const merged: string[] = [];
      for (const t of r.tags) merged.push(t);
      for (const t of extra) {
        if (merged.indexOf(t) < 0) merged.push(t);
      }
      await this.bridge.call('setTags',
        '{"id":' + JSON.stringify(r.id) + ',"tags":' + JSON.stringify(merged) + '}');
    }
    this.tagOpen = false;
    this.tagInput = '';
    this.requestList(true);
  }

  // 手动添加页的标签：仅暂存，保存时随条目一起提交
  private applyFormTag(): void {
    const t: string = this.tagInput.trim();
    if (t.length === 0) return;
    if (this.formTags.indexOf(t) < 0) {
      const next: string[] = this.formTags.slice();
      next.push(t);
      this.formTags = next;
    }
    this.tagForForm = false;
    this.tagInput = '';
  }

  private removeFormTag(t: string): void {
    const next: string[] = [];
    for (const x of this.formTags) {
      if (x !== t) next.push(x);
    }
    this.formTags = next;
  }

  // 表单可选标签 = 已有标签 + 本次新建（尚未被任何条目使用）的标签
  private formTagOptions(): string[] {
    const out: string[] = this.allTags();
    for (const t of this.formTags) {
      if (out.indexOf(t) < 0) out.push(t);
    }
    out.sort((a: string, b: string) => a < b ? -1 : (a > b ? 1 : 0));
    return out;
  }

  private toggleFormTag(t: string): void {
    if (this.formTags.indexOf(t) >= 0) {
      this.removeFormTag(t);
      return;
    }
    const next: string[] = this.formTags.slice();
    next.push(t);
    this.formTags = next;
  }

  @Builder
  selChip(label: string, icon: Resource, tap: () => void) {
    Row() {
      Text(this.tr(label))
        .fontSize(13)
        .fontColor(this.textColor())
      SymbolGlyph(icon)
        .fontSize(12)
        .fontColor([this.muted()])
        .margin({ left: 5 })
    }
    .padding({ left: 14, right: 12, top: 8, bottom: 8 })
    .backgroundColor(this.card())
    .borderRadius(18)
    .onClick(tap)
  }

  @Builder
  selAction(icon: Resource, label: string, danger: boolean, tap: () => void) {
    Column() {
      SymbolGlyph(icon)
        .fontSize(22)
        .fontColor([danger ? '#F53434' : this.textColor()])
      Text(this.tr(label))
        .fontSize(11)
        .fontColor(danger ? '#F53434' : this.muted())
        .margin({ top: 6 })
    }
    .layoutWeight(1)
    .height(62)
    .justifyContent(FlexAlign.Center)
    .backgroundColor(this.card())
    .borderRadius(12)
    .onClick(tap)
  }

  // 底部多选操作面板：全选 / 已选图标 / 已选数量，操作项随选择项变化
  @Builder
  selectionSheet() {
    Column() {
      Row() {
        this.selChip('全选', $r('sys.symbol.checkmark'), () => {
          this.selectAllVisible();
        })
        Blank()
        Row({ space: 6 }) {
          ForEach(this.selectedRows().slice(0, 3), (r: OtpRow) => {
            this.rowIcon(r, 22)
          }, (r: OtpRow) => 'selicon:' + r.id)
          if (this.selectedIds.length > 3) {
            Text('+' + (this.selectedIds.length - 3))
              .fontSize(11)
              .fontColor(this.faint())
          }
        }
        Blank()
        this.selChip(this.icuPlural('@selectedCount', this.selectedIds.length),
          $r('sys.symbol.xmark'), () => {
            this.exitSelection();
          })
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)

      Column({ space: 8 }) {
        if (!this.selectedAllTrashed()) {
          if (this.selectedIds.length === 1) {
            Row({ space: 8 }) {
              this.selAction($r('sys.symbol.square_and_pencil'), '编辑', false, () => {
                const one: OtpRow | null = this.selectedRows().length === 1 ? this.selectedRows()[0] : null;
                this.exitSelection();
                if (one !== null) this.openEdit(one);
              })
              this.selAction($r('sys.symbol.share'), '分享', false, () => {
                const one: OtpRow | null = this.selectedRows().length === 1 ? this.selectedRows()[0] : null;
                this.exitSelection();
                if (one !== null) this.shareRow(one);
              })
              this.selAction($r('sys.symbol.qrcode'), '二维码', false, () => {
                const one: OtpRow | null = this.selectedRows().length === 1 ? this.selectedRows()[0] : null;
                this.exitSelection();
                if (one !== null) this.openQr(one);
              })
            }
            .width('100%')
          }
          Row({ space: 8 }) {
            this.selAction(this.selectedAllPinned() ? $r('sys.symbol.pin_fill') : $r('sys.symbol.pin'),
              this.selectedAllPinned() ? '取消置顶' : '置顶', false, () => {
                this.pinSelected();
              })
            this.selAction($r('sys.symbol.label'), '添加标签', false, () => {
              this.tagOpen = true;
              this.tagInput = '';
            })
            this.selAction($r('sys.symbol.trash'), '回收站', true, () => {
              this.trashSelected();
            })
          }
          .width('100%')
        } else {
          Row({ space: 8 }) {
            this.selAction($r('sys.symbol.arrow_counterclockwise'), '恢复', false, () => {
              this.trashSelected();
            })
            this.selAction($r('sys.symbol.trash_fill'), '永久删除', true, () => {
              this.selDeleteConfirm = true;
            })
          }
          .width('100%')
        }
      }
      .width('100%')
      .margin({ top: 10 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(12)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .transition(TransitionEffect.translate({ y: 320 })
      .combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 添加标签（应用到所有选中条目）
  @Builder
  tagCard() {
    Column() {
      // 标题与计数均取自官方：createNewTag / selected
      Text(this.tr('创建新标签'))
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.selectedIds.length + ' ' + this.tr('已选'))
        .fontSize(12)
        .fontColor(this.muted())
        .width('100%')
        .margin({ top: 4 })
      if (this.tagOptions().length > 0) {
        Flex({ wrap: FlexWrap.Wrap }) {
          ForEach(this.tagOptions(), (t: string) => {
            Text(t)
              .fontSize(12)
              .fontColor(this.primary())
              .backgroundColor(this.selectedBg())
              .padding({ left: 10, right: 10, top: 6, bottom: 6 })
              .borderRadius(12)
              .margin({ right: 8, top: 8 })
          }, (t: string) => 'tag:' + t)
        }
        .width('100%')
        .margin({ top: 4 })
      }
      TextInput({ text: this.tagInput })
        .width('100%')
        .height(42)
        .fontSize(14)
        .backgroundColor(this.inputBg())
        .borderRadius(8)
        .placeholderColor(this.faint())
        .caretColor(this.primary())
        .margin({ top: 12 })
        .onChange((v: string) => {
          this.tagInput = v;
        })
      Row() {
        Button(this.tr('取消'))
          .height(42)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.tagOpen = false;
            this.tagInput = '';
          })
        Button(this.tr('创建'))
          .height(42)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.primary())
          .fontColor('#FFFFFF')
          .onClick(() => {
            this.applyTags();
          })
      }
      .width('100%')
      .margin({ top: 16 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .transition(TransitionEffect.translate({ y: 320 })
      .combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 永久删除二次确认
  @Builder
  selDeleteCard() {
    Column() {
      // 文案取自官方：deleteCodeTitle / deleteCodeMessage / delete
      Text(this.tr('要删除代码吗？'))
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('您确定要删除此代码吗？此操作不可逆。'))
        .fontSize(13)
        .fontColor(this.muted())
        .width('100%')
        .margin({ top: 8 })
      Row() {
        Button(this.tr('取消'))
          .height(42)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.selDeleteConfirm = false;
          })
        Button(this.tr('删除'))
          .height(42)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor('#F53434')
          .fontColor(Color.White)
          .onClick(() => {
            this.selDeleteConfirm = false;
            this.deleteSelectedForever();
          })
      }
      .width('100%')
      .margin({ top: 16 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .transition(TransitionEffect.translate({ y: 320 })
      .combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }


  @Builder
  drawerItem(icon: Resource, title: string, sub: string, tap: () => void) {
    Row() {
      SymbolGlyph(icon)
        .fontSize(20)
        .fontColor([this.muted()])
        .margin({ right: 14 })
      Column() {
        Text(this.tr(title))
          .fontSize(15)
          .fontColor(this.textColor())
        if (sub.length > 0) {
          Text(this.tr(sub))
            .fontSize(11)
            .fontColor(this.faint())
            .margin({ top: 2 })
        }
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)
      SymbolGlyph($r('sys.symbol.chevron_right'))
        .fontSize(16)
        .fontColor([this.faint()])
    }
    .width('100%')
    .height(sub.length > 0 ? 60 : 52)
    .padding({ left: 4, right: 4 })
    .borderRadius(8)
    .onClick(tap)
  }

  // 编辑顺序：排序单选项
  @Builder
  sortRadio(v: number, label: string) {
    Row() {
      Text(this.tr(label))
        .fontSize(15)
        .fontColor(this.textColor())
      Blank()
      Stack() {
        if (this.sortMode === v) {
          SymbolGlyph($r('sys.symbol.checkmark'))
            .fontSize(12)
            .fontColor([Color.White])
        }
      }
      .width(20)
      .height(20)
      .borderRadius(10)
      .backgroundColor(this.sortMode === v ? this.primary() : Color.Transparent)
      .border({ width: 1.5, color: this.primary() })
    }
    .width('100%')
    .height(this.landscape ? 36 : 46)
    .onClick(() => {
      this.setSortMode(v);
    })
  }

  @Builder
  sortCard() {
    Column() {
      Row() {
        Text(this.tr('编辑顺序'))
          .fontSize(16)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.textColor())
        Blank()
        Button({ type: ButtonType.Normal }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(18)
            .fontColor([this.muted()])
        }
        .width(36)
        .height(36)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.sortOpen = false;
        })
      }
      .width('100%')
      .height(40)

      Column() {
        this.sortRadio(SORT_ISSUER, '发行方')
        this.sortRadio(SORT_ACCOUNT, '账户')
        this.sortRadio(SORT_FREQUENT, '经常使用')
        this.sortRadio(SORT_RECENT, '最近使用')
        this.sortRadio(SORT_CUSTOM, '自定义')
      }
      .width('100%')

      if (this.sortMode === SORT_CUSTOM) {
        Divider()
          .color(this.divider())
          .margin({ top: 6, bottom: 6 })
        Scroll() {
          Column() {
            ForEach(this.visibleRows(), (r: OtpRow) => {
              Row() {
                this.rowIcon(r, 22)
                Text(this.titleOf(r))
                  .fontSize(14)
                  .fontColor(this.textColor())
                  .maxLines(1)
                  .textOverflow({ overflow: TextOverflow.Ellipsis })
                  .layoutWeight(1)
                  .margin({ left: 10 })
                SymbolGlyph($r('sys.symbol.chevron_up'))
                  .fontSize(18)
                  .fontColor([this.muted()])
                  .padding(6)
                  .onClick(() => {
                    this.moveCustom(r.id, -1);
                  })
                SymbolGlyph($r('sys.symbol.chevron_down'))
                  .fontSize(18)
                  .fontColor([this.muted()])
                  .padding(6)
                  .onClick(() => {
                    this.moveCustom(r.id, 1);
                  })
              }
              .width('100%')
              .height(46)
            }, (r: OtpRow) => 'ord:' + r.id)
          }
          .width('100%')
        }
        .width('100%')
        .height(this.landscape ? 90 : 210)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
    }
    .width('92%')
    .constraintSize({ maxWidth: 520, maxHeight: '92%' })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .shadow({ radius: 16, color: '#1A000000', offsetX: 0, offsetY: 4 })
    .transition(TransitionEffect.translate({ y: 320 })
      .combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  drawer() {
    Column() {
      Row() {
        Text(this.tr('设置'))
          .fontSize(24)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(18)
            .fontColor([this.textColor()])
        }
        .width(36)
        .height(36)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.drawerOpen = false;
        })
      }
      .width('100%')
      .margin({ bottom: 2 })

      // 账号名对齐官方：显示在「设置」标题下方
      Text(this.userEmail)
        .fontSize(12)
        .fontColor(this.muted())
        .width('100%')
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .margin({ bottom: 8 })

      Scroll() {
        Column() {
          this.drawerItem($r('sys.symbol.person'), '账户', '', () => {
            this.openPage('account');
          })
          this.drawerItem($r('sys.symbol.square_and_arrow_down'), '数据', '', () => {
            this.openPage('data');
          })
          this.drawerItem($r('sys.symbol.lock'), '安全', '', () => {
            this.openPage('security');
          })
          this.drawerItem($r('sys.symbol.paintpalette'), '主题', '', () => {
            this.openPage('theme');
          })
          this.drawerItem($r('sys.symbol.gearshape'), '通用', '', () => {
            this.openPage('general');
          })
          this.drawerItem($r('sys.symbol.questionmark_circle'), '支持', '', () => {
            this.openPage('support');
          })
          this.drawerItem($r('sys.symbol.info_circle'), '关于', '', () => {
            this.openPage('about');
          })

          Divider().color(this.divider()).margin({ top: 6, bottom: 6 })

          // 退出登录紧跟「关于」，与官方一致
          Row() {
            SymbolGlyph($r('sys.symbol.power'))
              .fontSize(18)
              .fontColor(['#F53434'])
              .margin({ right: 12 })
            Text(this.tr('退出登录'))
              .fontSize(15)
              .fontColor('#F53434')
              .layoutWeight(1)
          }
          .width('100%')
          .height(52)
          .padding({ left: 4, right: 4 })
          .onClick(() => {
            this.drawerOpen = false;
            this.logoutConfirm = true;
          })

          // 底部：更多 Ente 应用、社交链接与版本号（对齐官方设置页）
          Column() {
            // 品牌字标固定英文，不参与多语言
            Text('More from')
              .fontSize(26.279)
              .fontFamily('Gochi Hand')
              .fontColor(this.primary())
              .letterSpacing(-1.05)
              .lineHeight(26.8)
            Image($rawfile('icons/ente_wordmark.svg'))
              .width(62)
              .height(18.43)
              .fillColor(this.textColor())
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
          .margin({ top: 40, bottom: 16 })

          Row({ space: 39 }) {
            Column() {
              Stack() {
                Image($rawfile('icons/photos.png'))
                  .width(31)
                  .height(31)
              }
              .width(52)
              .height(52)
              .backgroundColor(this.card())
              .borderRadius(16.774)
              Text('Photos')
                .fontSize(13)
                .fontColor(this.textColor())
                .margin({ top: 8 })
            }
            .onClick(() => {
              this.openUrl('https://ente.com/?from=auth');
            })

            Column() {
              Stack() {
                Image($rawfile('icons/locker.png'))
                  .width(31)
                  .height(31)
              }
              .width(52)
              .height(52)
              .backgroundColor(this.card())
              .borderRadius(16.774)
              Text('Locker')
                .fontSize(13)
                .fontColor(this.textColor())
                .margin({ top: 8 })
            }
            .onClick(() => {
              this.openUrl('https://ente.com/locker?from=auth');
            })
          }
          .width('100%')
          .justifyContent(FlexAlign.Center)

          Row() {
            Stack() {
              Image(this.dark ? $rawfile('icons/github_outline_white.svg') : $rawfile('icons/github_outline_black.svg'))
                .width(18)
                .height(18)
            }
            .width(36)
            .height(36)
            .borderRadius(12)
            .onClick(() => {
              this.openUrl('https://github.com/ente/ente');
            })
          }
          .width('100%')
          .margin({ top: 40 })
          .justifyContent(FlexAlign.Center)

          Text(this.appVersion.length > 0 ? 'Version ' + this.appVersion : '')
            .fontSize(11)
            .fontColor(this.faint())
            .width('100%')
            .textAlign(TextAlign.Center)
            .margin({ top: 12, bottom: 24 })
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      }
      .layoutWeight(1)
      .width('100%')
      .scrollBar(BarState.Off)
      .edgeEffect(EdgeEffect.Spring)
    }
    .width('100%')
    .height('100%')
    .padding({ left: 20, right: 20, top: this.topInset + 20 })
    .backgroundColor(this.bg())
    .alignItems(HorizontalAlign.Start)
    .shadow({ radius: 20, color: '#26000000', offsetX: 0, offsetY: 0 })
    .transition(TransitionEffect.translate({ x: -360, y: 0 })
      .animation({ duration: 220, curve: Curve.EaseOut }))
  }

  @Builder
  logoutCard() {
    Column() {
      Text(this.tr('您确定要退出登录吗？'))
        .fontSize(15)
        .fontColor(this.dangerText())
        .margin({ bottom: 6 })
      Text(this.tr('这将使您从此设备退出登录！'))
        .fontSize(12)
        .fontColor(this.muted())
        .margin({ bottom: 14 })
      Row() {
        Button(this.tr('取消'))
          .height(40)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.logoutConfirm = false;
          })
        Button(this.tr('退出登录'))
          .height(40)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor('#D32F2F')
          .onClick(() => {
            this.logoutConfirm = false;
            this.logout();
          })
      }
      .width('100%')
    }
    .width('82%')
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.OPACITY
      .combine(TransitionEffect.scale({ x: 0.92, y: 0.92 }))
      .animation({ duration: 200, curve: Curve.Friction }))
  }

  // ---------- 账户页底部弹层 ----------

  @Builder
  exportOption(title: string, action: () => void) {
    Row() {
      Text(this.tr(title))
        .fontSize(15)
        .fontColor(this.textColor())
        .layoutWeight(1)
      SymbolGlyph($r('sys.symbol.chevron_right'))
        .fontSize(16)
        .fontColor([this.faint()])
    }
    .width('100%')
    .padding({ top: 12, bottom: 12 })
    .onClick(action)
  }

  @Builder
  exportSheet() {
    Column() {
      Row() {
        Text(this.exportStep === 0 ? this.tr('选择导出格式') : (this.exportStep === 1 ? this.tr('用来加密导出的密码') : this.tr('警告')))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.exportOpen = false;
        })
      }
      .width('100%')

      if (this.exportStep === 0) {
        Text(this.tr('加密导出将由您选择的密码保护。'))
          .fontSize(12)
          .fontColor(this.muted())
          .width('100%')
          .margin({ top: 8, bottom: 4 })
        this.exportOption('已加密', () => {
          this.exportFormat = 'encrypted';
          this.exportPwd = '';
          this.exportStep = 1;
        })
        Divider().color(this.divider())
        this.exportOption('纯文本', () => {
          this.exportFormat = 'txt';
          this.exportStep = 2;
        })
        Divider().color(this.divider())
        this.exportOption('纯 HTML', () => {
          this.exportFormat = 'html';
          this.exportStep = 2;
        })
      } else if (this.exportStep === 1) {
        TextInput({ text: this.exportPwd, placeholder: this.tr('输入密码') })
          .width('100%')
          .height(44)
          .margin({ top: 12 })
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .type(InputType.Password)
          .onChange((v: string) => {
            this.exportPwd = v;
          })
        Row() {
          Button(this.tr('返回'))
            .height(44)
            .layoutWeight(1)
            .backgroundColor(this.chipBg())
            .fontColor(this.textColor())
            .onClick(() => {
              this.exportStep = 0;
            })
          Button(this.tr('导出'))
            .height(44)
            .layoutWeight(1)
            .margin({ left: 10 })
            .backgroundColor(this.primary())
            .enabled(!this.exportBusy)
            .onClick(() => {
              this.runExport();
            })
        }
        .width('100%')
        .margin({ top: 14 })
      } else {
        Text(this.tr('导出的文件包含敏感信息。请安全存储。'))
          .fontSize(12)
          .fontColor(this.muted())
          .lineHeight(18)
          .width('100%')
          .margin({ top: 8 })
        Row() {
          Button(this.tr('取消'))
            .height(44)
            .layoutWeight(1)
            .backgroundColor(this.chipBg())
            .fontColor(this.textColor())
            .onClick(() => {
              this.exportStep = 0;
            })
          Button(this.tr('了解'))
            .height(44)
            .layoutWeight(1)
            .margin({ left: 10 })
            .backgroundColor(this.orange())
            .enabled(!this.exportBusy)
            .onClick(() => {
              this.runExport();
            })
        }
        .width('100%')
        .margin({ top: 14 })
      }
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  importPwdSheet() {
    Column() {
      Row() {
        Text(this.tr('用来解密导出的密码'))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.importPwdOpen = false;
          this.importFileText = '';
        })
      }
      .width('100%')

      TextInput({ text: this.importPwd, placeholder: this.tr('输入您的密码') })
        .width('100%')
        .height(44)
        .margin({ top: 12 })
        .backgroundColor(this.chipBg())
        .fontColor(this.textColor())
        .type(InputType.Password)
        .onChange((v: string) => {
          this.importPwd = v;
        })
      Row() {
        Button(this.tr('取消'))
          .height(44)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.importPwdOpen = false;
            this.importFileText = '';
          })
        Button(this.tr('导入'))
          .height(44)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.primary())
          .enabled(!this.importBusy)
          .onClick(() => {
            this.confirmImportPwd();
          })
      }
      .width('100%')
      .margin({ top: 14 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  backupPwdSheet() {
    Column() {
      Row() {
        Text(this.backupPwdSet ? this.tr('更新备份密码') : this.tr('设置备份密码'))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.backupPwdOpen = false;
        })
      }
      .width('100%')

      Text(this.tr('您的备份将使用此密码加密。'))
        .fontSize(12)
        .fontColor(this.muted())
        .lineHeight(18)
        .width('100%')
        .margin({ top: 8 })
      TextInput({ text: this.backupPwdInput, placeholder: this.tr('输入密码') })
        .width('100%')
        .height(44)
        .margin({ top: 12 })
        .backgroundColor(this.chipBg())
        .fontColor(this.textColor())
        .type(InputType.Password)
        .onChange((v: string) => {
          this.backupPwdInput = v;
        })
      Row() {
        Button(this.tr('取消'))
          .height(44)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.backupPwdOpen = false;
          })
        Button(this.tr('保存'))
          .height(44)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.primary())
          .onClick(() => {
            this.saveBackupPwd();
          })
      }
      .width('100%')
      .margin({ top: 14 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 导入说明弹层（对齐官方 instruction sheet：应用名标题 + 官方引导文案 + 对应动作按钮）
  @Builder
  importGuideSheet() {
    Column() {
      Row() {
        Text(this.importGuideTitle(this.importGuideApp))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.importGuideApp = '';
        })
      }
      .width('100%')

      Text(this.importGuideBody(this.importGuideApp))
        .fontSize(13)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 10 })

      if (this.importGuideApp === 'plain') {
        // 对齐官方纯文本导入：示例格式 + 分隔符说明
        Text('otpauth://totp/provider.com:you@email.com?secret=YOUR_SECRET')
          .fontSize(12)
          .fontColor(this.textColor())
          .width('100%')
          .padding(10)
          .margin({ top: 12 })
          .backgroundColor(this.chipBg())
          .borderRadius(8)
        Text(this.tr('代码可以用逗号或换行符分隔'))
          .fontSize(13)
          .fontColor(this.muted())
          .lineHeight(20)
          .width('100%')
          .margin({ top: 10 })
      }

      Button(this.importGuideAction(this.importGuideApp))
        .width('100%')
        .height(44)
        .margin({ top: 16 })
        .backgroundColor(this.primary())
        .onClick(() => {
          this.runImportGuideAction(this.importGuideApp);
        })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 导入成功弹层（对齐官方 importSuccessDialog：耶！+ 导入数量 + 确定）
  @Builder
  importSuccessSheet() {
    Column() {
      Text(this.tr('耶！'))
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('@importSuccessDesc').replace('{count}', this.importSuccessCount.toString()))
        .fontSize(13)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 10 })
      Button(this.tr('确定'))
        .width('100%')
        .height(44)
        .margin({ top: 16 })
        .backgroundColor(this.primary())
        .onClick(() => {
          this.importSuccessCount = -1;
        })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 删除重复确认弹层（对齐官方：删除重复项 + 移入回收站数量确认）
  @Builder
  dupConfirmSheet() {
    Column() {
      Text(this.tr('删除重复项'))
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('@moveMultipleToTrashMessage').replace('{count}', this.dupSelectedExtras().toString()))
        .fontSize(13)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 10 })
      Row() {
        Button(this.tr('取消'))
          .height(44)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.dupConfirmOpen = false;
          })
        Button(this.tr('回收站'))
          .height(44)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.orange())
          .onClick(() => {
            this.trashSelectedDuplicates();
          })
      }
      .width('100%')
      .margin({ top: 16 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // 无重复代码提示（对齐官方：✨ 没有重复项 + 说明 + 确定）
  @Builder
  noDupCard() {
    Column() {
      Text(this.tr('✨ 没有重复项'))
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('您没有可清除的重复代码'))
        .fontSize(13)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 10 })
      Button(this.tr('确定'))
        .width('100%')
        .height(44)
        .margin({ top: 16 })
        .backgroundColor(this.primary())
        .onClick(() => {
          this.noDupOpen = false;
        })
    }
    .width('94%')
    .constraintSize({ maxWidth: 420 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.OPACITY
      .animation({ duration: 200 }))
  }

  @Builder
  emailSheet() {
    Column() {
      Row() {
        Text(this.tr('更改电子邮件'))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.emailOpen = false;
        })
      }
      .width('100%')

      if (this.emailStep === 0) {
        TextInput({ text: this.newEmail, placeholder: this.tr('请输入您的新电子邮件地址') })
          .width('100%')
          .height(44)
          .margin({ top: 16 })
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .type(InputType.Email)
          .onChange((v: string) => {
            this.newEmail = v;
          })
        Button(this.tr('发送 OTP'))
          .width('100%')
          .height(44)
          .margin({ top: 12 })
          .backgroundColor(this.primary())
          .enabled(!this.acctBusy)
          .onClick(() => {
            this.sendEmailOtt();
          })
      } else {
        Text(this.tr('@weHaveSentCode').replace('{email}', this.newEmail))
          .fontSize(12)
          .fontColor(this.muted())
          .width('100%')
          .margin({ top: 12 })
        TextInput({ text: this.emailOtt })
          .width('100%')
          .height(44)
          .margin({ top: 10 })
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onChange((v: string) => {
            this.emailOtt = v;
          })
        Row() {
          Button(this.tr('返回'))
            .height(42)
            .layoutWeight(1)
            .backgroundColor(this.chipBg())
            .fontColor(this.textColor())
            .onClick(() => {
              this.emailStep = 0;
            })
          Button(this.tr('验证'))
            .height(42)
            .layoutWeight(1)
            .margin({ left: 10 })
            .backgroundColor(this.primary())
            .enabled(!this.acctBusy)
            .onClick(() => {
              this.confirmChangeEmail();
            })
        }
        .width('100%')
        .margin({ top: 12 })
      }
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  recoverySheet() {
    Column() {
      Row() {
        Text(this.tr('恢复密钥'))
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(15)
            .fontColor([this.textColor()])
        }
        .width(36)
        .height(36)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.recoveryOpen = false;
        })
      }
      .width('100%')

      Text(this.tr('如果您忘记了密码，恢复数据的唯一方法就是使用此密钥。'))
        .fontSize(14)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 16 })

      // 官方样式：深紫底 + 白色等宽密钥文本，右上角复制
      Stack({ alignContent: Alignment.TopEnd }) {
        Scroll() {
          Text(this.recoveryWords)
            .fontSize(15)
            .fontWeight(FontWeight.Medium)
            .fontFamily('monospace')
            .fontColor(Color.White)
            .letterSpacing(0.5)
            .lineHeight(22)
            .textAlign(TextAlign.JUSTIFY)
            .width('100%')
            .padding({ left: 24, right: 44, top: 22, bottom: 22 })
            .copyOption(CopyOptions.LocalDevice)
        }
        .width('100%')
        .constraintSize({ maxHeight: 220 })
        .scrollBar(BarState.Off)

        Button({ type: ButtonType.Normal }) {
          SymbolGlyph($r('sys.symbol.rectangle_on_rectangle'))
            .fontSize(20)
            .fontColor(['#FFE0CCFF'])
        }
        .width(36)
        .height(36)
        .borderRadius(8)
        .backgroundColor(Color.Transparent)
        .margin({ top: 8, right: 8 })
        .onClick(() => {
          this.copyRecoveryKey();
        })
      }
      .width('100%')
      .backgroundColor('#FF722ED1')
      .borderRadius(16)
      .margin({ top: 20 })

      Text(this.tr('我们不会存储此密钥，请将这 24 个单词的密钥保存在安全的地方。'))
        .fontSize(14)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 16 })

      // 官方 GradientButton：渐变色、56 高、4 圆角、白色 18 号中等字重
      Button(this.tr('保存密钥'))
        .width('100%')
        .height(56)
        .margin({ top: 24 })
        .linearGradient({
          angle: 135,
          colors: [['#FFB37FEB', 0.0], ['#FF22075E', 1.0]],
        })
        .fontSize(18)
        .fontWeight(FontWeight.Medium)
        .fontColor(Color.White)
        .borderRadius(4)
        .onClick(() => {
          this.shareRecoveryKey();
        })
    }
    .width('100%')
    .padding({ left: 24, right: 24, top: 20, bottom: 36 })
    .backgroundColor(this.elevated())
    .borderRadius({ topLeft: 24, topRight: 24 })
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  emailMfaWarnSheet() {
    Column() {
      Text(this.tr('警告'))
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('为避免被锁在您的账户之外，请在启用电子邮件验证之前确保在 Ente Auth 之外存储电子邮件双重认证的副本。'))
        .fontSize(14)
        .fontColor(this.muted())
        .lineHeight(20)
        .width('100%')
        .margin({ top: 12 })

      Row() {
        Button(this.tr('取消'))
          .layoutWeight(1)
          .height(48)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .fontSize(15)
          .onClick(() => {
            this.emailMfaWarnOpen = false;
            this.emailMfaEnabled = false;
          })
        Button(this.tr('了解'))
          .layoutWeight(1)
          .height(48)
          .margin({ left: 12 })
          .backgroundColor(this.primary())
          .fontColor(Color.White)
          .fontSize(15)
          .onClick(() => {
            this.emailMfaWarnOpen = false;
            this.applyEmailMfa(true);
          })
      }
      .width('100%')
      .margin({ top: 24 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.scale({ x: 0.94, y: 0.94 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 220, curve: Curve.Friction }))
  }

  @Builder
  sessionsSheet() {
    Column() {
      Row() {
        Text(this.tr('活跃会话'))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.sessionsOpen = false;
        })
      }
      .width('100%')

      if (this.sessionsLoading) {
        LoadingProgress()
          .width(32)
          .height(32)
          .color(this.primary())
          .margin({ top: 24, bottom: 24 })
      } else {
        Scroll() {
          Column() {
            ForEach(this.sessions, (s: SessionInfo) => {
              Row() {
                SymbolGlyph($r('sys.symbol.phone'))
                  .fontSize(18)
                  .fontColor([this.muted()])
                  .margin({ right: 10 })
                Column() {
                  Text(this.sessionLabel(s))
                    .fontSize(13)
                    .fontColor(this.textColor())
                    .maxLines(1)
                    .textOverflow({ overflow: TextOverflow.Ellipsis })
                  Text(s.ip + (s.isCurrent ? ' · ' + this.tr('此设备') : ''))
                    .fontSize(11)
                    .fontColor(s.isCurrent ? this.primary() : this.faint())
                    .margin({ top: 2 })
                }
                .layoutWeight(1)
                .alignItems(HorizontalAlign.Start)
                if (!s.isCurrent) {
                  Button(this.tr('终止'))
                    .height(30)
                    .fontSize(12)
                    .backgroundColor(this.chipBg())
                    .fontColor('#F53434')
                    .onClick(() => {
                      this.terminateSession(s.token);
                    })
                }
              }
              .width('100%')
              .padding({ top: 10, bottom: 10 })
            }, (s: SessionInfo) => s.token)
          }
          .width('100%')
        }
        .height(260)
        .width('100%')
        .scrollBar(BarState.Off)
      }

      Button(this.tr('完成'))
        .width('100%')
        .height(44)
        .margin({ top: 8 })
        .backgroundColor(this.primary())
        .onClick(() => {
          this.sessionsOpen = false;
        })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  noteCard() {
    Column() {
      Row() {
        Text(this.tr('备注'))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.noteOpen = false;
        })
      }
      .width('100%')

      TextArea({ text: this.noteText })
        .width('100%')
        .height(120)
        .margin({ top: 12 })
        .backgroundColor(this.inputBg())
        .borderRadius(8)
        .onChange((v: string) => {
          this.noteText = v;
        })

      Row() {
        Button(this.tr('取消'))
          .height(44)
          .layoutWeight(1)
          .backgroundColor(this.chipBg())
          .fontColor(this.textColor())
          .onClick(() => {
            this.noteOpen = false;
          })
        Button(this.tr('保存'))
          .height(44)
          .layoutWeight(1)
          .margin({ left: 10 })
          .backgroundColor(this.primary())
          .onClick(() => {
            this.saveNote();
          })
      }
      .width('100%')
      .margin({ top: 14 })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 300 })
      .combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  // ---------- 二级页面（Navigation 入栈，标题栏自带返回） ----------

  @Builder
  pageMap(name: string) {
    if (name === 'about') {
      this.aboutPage()
    } else if (name === 'qrcode') {
      this.qrPage()
    } else if (name === 'form') {
      this.formPage()
    } else if (name === 'account') {
      this.accountPage()
    } else if (name === 'changePwd') {
      this.changePwdPage()
    } else if (name === 'data') {
      this.dataPage()
    } else if (name === 'import') {
      this.importPage()
    } else if (name === 'backup') {
      this.backupPage()
    } else if (name === 'lock') {
      this.lockPage()
    } else if (name === 'security') {
      this.securityPage()
    } else if (name === 'theme') {
      this.themePage()
    } else if (name === 'general') {
      this.generalPage()
    } else if (name === 'trash') {
      this.trashPage()
    } else if (name === 'duplicates') {
      this.duplicatesPage()
    } else if (name === 'support') {
      this.supportPage()
    }
  }

  // 自定义标题栏：入栈页面统一返回按钮与沉浸式配色
  @Builder
  pageHeader(title: string) {
    Row() {
      Button({ type: ButtonType.Circle }) {
        SymbolGlyph($r('sys.symbol.arrow_left'))
          .fontSize(20)
          .fontColor([this.textColor()])
      }
      .width(40)
      .height(40)
      .backgroundColor(Color.Transparent)
      .attributeModifier(this.matBtnUltraThin)
      .onClick(() => {
        this.pathStack.pop();
      })
      Text(this.tr(title))
        .fontSize(18)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.textColor())
        .margin({ left: 4 })
        .layoutWeight(1)
    }
    .width('100%')
    .height(56 + this.topInset)
    .padding({ left: 8, right: 16, top: this.topInset })
    .backgroundColor(this.bg())
    .alignItems(VerticalAlign.Center)
  }

  // ---------- 设置页通用行 ----------

  @Builder
  navRow(icon: Resource, title: string, sub: string, danger: boolean, tap: () => void) {
    Row() {
      SymbolGlyph(icon)
        .fontSize(20)
        .fontColor([danger ? '#F53434' : this.muted()])
        .margin({ right: 14 })
      Column() {
        Text(this.tr(title))
          .fontSize(15)
          .fontColor(danger ? '#F53434' : this.textColor())
        if (sub.length > 0) {
          Text(this.tr(sub))
            .fontSize(11)
            .fontColor(this.faint())
            .margin({ top: 2 })
        }
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)
      if (!danger) {
        SymbolGlyph($r('sys.symbol.chevron_right'))
          .fontSize(16)
          .fontColor([this.faint()])
      }
    }
    .width('100%')
    .height(sub.length > 0 ? 60 : 52)
    .padding({ left: 14, right: 14 })
    .onClick(tap)
  }

  @Builder
  toggleRow(icon: Resource, title: string, sub: string, on: boolean, change: (v: boolean) => void) {
    Row() {
      SymbolGlyph(icon)
        .fontSize(20)
        .fontColor([this.muted()])
        .margin({ right: 14 })
      Column() {
        Text(this.tr(title))
          .fontSize(15)
          .fontColor(this.textColor())
        if (sub.length > 0) {
          Text(this.tr(sub))
            .fontSize(11)
            .fontColor(this.faint())
            .margin({ top: 2 })
        }
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)
      Toggle({ type: ToggleType.Switch, isOn: on })
        .selectedColor(this.primary())
        .onChange(change)
    }
    .width('100%')
    .height(sub.length > 0 ? 62 : 52)
    .padding({ left: 14, right: 14 })
  }

  @Builder
  themeRow(icon: Resource, title: string, mode: number, tap: () => void) {
    Row() {
      SymbolGlyph(icon)
        .fontSize(20)
        .fontColor([this.themeMode === mode ? this.primary() : this.muted()])
        .margin({ right: 14 })
      Text(this.tr(title))
        .fontSize(15)
        .fontColor(this.textColor())
        .layoutWeight(1)
      SymbolGlyph($r('sys.symbol.checkmark'))
        .fontSize(16)
        .fontColor([this.primary()])
        .opacity(this.themeMode === mode ? 1 : 0)
    }
    .width('100%')
    .height(54)
    .padding({ left: 14, right: 14 })
    .onClick(tap)
  }

  @Builder
  aboutPage() {
    NavDestination() {
      Column() {
        this.pageHeader('关于')
        Scroll() {
        Column() {
          Text('ente Auth')
            .fontSize(24)
            .fontWeight(FontWeight.Bold)
            .fontColor(this.textColor())
          Text(this.tr('HarmonyOS 原生壳 · 复用 Ente Auth 的端到端加密与同步'))
            .fontSize(12)
            .fontColor(this.muted())
            .margin({ top: 8 })

          Column() {
            Text(this.tr('加密说明'))
              .fontSize(13)
              .fontColor(this.textColor())
              .fontWeight(FontWeight.Medium)
            Text(this.tr('密钥盒：XSalsa20-Poly1305\n条目：XChaCha20-Poly1305\n本地缓存：HUKS AES-256-CBC'))
              .fontSize(12)
              .fontColor(this.muted())
              .margin({ top: 8 })
              .lineHeight(22)
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          .padding(16)
          .backgroundColor(this.card())
          .borderRadius(8)
          .margin({ top: 20 })

          Column() {
            Text(this.tr('开源与声明'))
              .fontSize(13)
              .fontColor(this.textColor())
              .fontWeight(FontWeight.Medium)
            Text(this.tr('本项目是社区维护的 HarmonyOS 客户端，基于 Ente 开源项目（AGPL-3.0）构建，并非 Ente 官方发布。'))
              .fontSize(12)
              .fontColor(this.muted())
              .margin({ top: 8 })
              .lineHeight(20)
            Text(this.tr('应用完全非营利：无广告、无内购。所有验证码均在本机端到端加密后同步至您自己的 Ente 账户，我们不会收集任何数据。'))
              .fontSize(12)
              .fontColor(this.muted())
              .margin({ top: 6 })
              .lineHeight(20)
            Text(this.tr('请遵守上游项目的开源协议，并支持 Ente 官方产品。'))
              .fontSize(12)
              .fontColor(this.muted())
              .margin({ top: 6 })
              .lineHeight(20)
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          .padding(16)
          .backgroundColor(this.card())
          .borderRadius(8)
          .margin({ top: 12 })

          Column() {
            this.navRow($r('sys.symbol.link'), 'GitHub',
              'RengeRenge/Ente-Auth-for-HarmonyOS', false, () => {
                this.openUrl(REPO_URL);
              })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.lock'), this.tr('隐私政策'), '', false, () => {
              this.openUrl(PRIVACY_URL);
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.doc_plaintext'), this.tr('用户协议'), '', false, () => {
              this.openUrl(TERMS_URL);
            })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(8)
          .margin({ top: 12 })

          Text(this.tr('Ente Auth for HarmonyOS · 端到端加密'))
            .fontSize(11)
            .fontColor(this.faint())
            .margin({ top: 24 })
          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  // ---------- 设置二级页：账户 / 数据 / 安全 / 主题 / 通用 / 回收站 / 支持 ----------

  @Builder
  accountPage() {
    NavDestination() {
      Column() {
        this.pageHeader('账户')
        Scroll() {
        Column() {
          Column() {
            Row() {
              SymbolGlyph($r('sys.symbol.person_fill'))
                .fontSize(22)
                .fontColor([this.primary()])
                .margin({ right: 12 })
              Column() {
                Text(this.userEmail)
                  .fontSize(16)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(this.textColor())
                  .maxLines(1)
                  .textOverflow({ overflow: TextOverflow.Ellipsis })
              }
              .layoutWeight(1)
              .alignItems(HorizontalAlign.Start)
            }
            .width('100%')
            .padding(16)
            .backgroundColor(this.card())
            .borderRadius(12)

            Column() {
              this.navRow($r('sys.symbol.envelope'), '更改电子邮件', '', false, () => {
                this.openEmailSheet();
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.key'), '修改密码', '', false, () => {
                this.cpPwd = '';
                this.cpPwdConfirm = '';
                this.cpError = '';
                this.cpVisible = false;
                this.openPage('changePwd');
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.lock'), '恢复密钥', '', false, () => {
                this.loadRecoveryKey();
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.trash'), '删除账户', '', true, () => {
                this.confirmDeleteAccount();
              })
            }
            .width('100%')
            .backgroundColor(this.card())
            .borderRadius(12)
            .margin({ top: 16 })

            Blank()
          }
          .width('100%')
          .padding(20)
          .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        }
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  // 修改密码原生页：复刻官方 PasswordEntryPage（update 模式）——
  // 标题 + 副标题 + 密码警告 + 有效值着色输入框（聚焦眼睛 / 有效对勾后缀）+
  // 强度提示 + "工作原理?" 链接 + FAB + "退出其他设备"底部弹层
  @Builder
  changePwdPage() {
    NavDestination() {
      Stack() {
        Column() {
          this.pageHeader('修改密码')
          Scroll() {
            Column() {
              Text(this.tr('修改密码'))
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
                .fontColor(this.textColor())
              Text(this.tr('输入我们可以用来加密您的数据的新密码'))
                .fontSize(13)
                .fontColor(this.muted())
                .margin({ top: 8 })
                .lineHeight(19)
              Text(this.tr('我们不存储此密码，因此如果您忘记了它，<underline>我们将无法解密您的数据</underline>')
                .replace('<underline>', '').replace('</underline>', ''))
                .fontSize(12)
                .fontColor(this.muted())
                .margin({ top: 8 })
                .lineHeight(18)

              Text(this.tr('密码'))
                .fontSize(14)
                .fontWeight(FontWeight.Bold)
                .fontColor(this.textColor())
                .margin({ top: 24 })
              Stack({ alignContent: Alignment.End }) {
                TextInput({ text: this.cpPwd, placeholder: this.tr('输入您的密码') })
                  .type(this.cpVisible ? InputType.Normal : InputType.Password)
                  .showPasswordIcon(false)
                  .height(48)
                  .width('100%')
                  .padding({ left: 16, right: 48 })
                  .fontSize(14)
                  .fontColor(this.textColor())
                  .backgroundColor(Color.Transparent)
                  .caretColor(this.primary())
                  .enterKeyType(EnterKeyType.Next)
                  .enabled(!this.cpBusy)
                  .onFocus(() => {
                    this.cpFocus1 = true;
                  })
                  .onBlur(() => {
                    this.cpFocus1 = false;
                  })
                  .onChange((v: string) => {
                    this.cpPwd = v;
                    this.cpError = '';
                  })
                if (this.cpFocus1) {
                  Button({ type: ButtonType.Normal, stateEffect: false }) {
                    SymbolGlyph(this.cpVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
                      .fontSize(20)
                      .fontColor([this.muted()])
                  }
                  .width(28)
                  .height(28)
                  .margin({ right: 12 })
                  .padding(0)
                  .backgroundColor(Color.Transparent)
                  .onClick(() => {
                    this.cpVisible = !this.cpVisible;
                  })
                } else if (this.cpValid()) {
                  SymbolGlyph($r('sys.symbol.checkmark'))
                    .fontSize(20)
                    .fontColor([this.primary()])
                    .margin({ right: 14 })
                }
              }
              .width('100%')
              .height(48)
              .borderRadius(8)
              .backgroundColor(this.cpValid() ? this.cpFieldTint() : this.card())

              if (this.cpPwd.length > 0 && this.cpFocus1) {
                Text(this.pwStrengthText(this.cpPwd))
                  .fontSize(12)
                  .lineHeight(16)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(this.pwStrengthColor(this.pwStrength(this.cpPwd)))
                  .width('100%')
                  .margin({ top: 8 })
              }

              Text(this.tr('请确认密码'))
                .fontSize(14)
                .fontWeight(FontWeight.Bold)
                .fontColor(this.textColor())
                .margin({ top: 16 })
              Stack({ alignContent: Alignment.End }) {
                TextInput({ text: this.cpPwdConfirm, placeholder: this.tr('输入您的密码') })
                  .type(this.cpVisible ? InputType.Normal : InputType.Password)
                  .showPasswordIcon(false)
                  .height(48)
                  .width('100%')
                  .padding({ left: 16, right: 48 })
                  .fontSize(14)
                  .fontColor(this.textColor())
                  .backgroundColor(Color.Transparent)
                  .caretColor(this.primary())
                  .enterKeyType(EnterKeyType.Done)
                  .enabled(!this.cpBusy)
                  .onFocus(() => {
                    this.cpFocus2 = true;
                  })
                  .onBlur(() => {
                    this.cpFocus2 = false;
                  })
                  .onChange((v: string) => {
                    this.cpPwdConfirm = v;
                    this.cpError = '';
                  })
                  .onSubmit(() => {
                    this.cpStartChange();
                  })
                if (this.cpFocus2) {
                  Button({ type: ButtonType.Normal, stateEffect: false }) {
                    SymbolGlyph(this.cpVisible ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
                      .fontSize(20)
                      .fontColor([this.muted()])
                  }
                  .width(28)
                  .height(28)
                  .margin({ right: 12 })
                  .padding(0)
                  .backgroundColor(Color.Transparent)
                  .onClick(() => {
                    this.cpVisible = !this.cpVisible;
                  })
                } else if (this.cpMatch()) {
                  SymbolGlyph($r('sys.symbol.checkmark'))
                    .fontSize(20)
                    .fontColor([this.primary()])
                    .margin({ right: 14 })
                }
              }
              .width('100%')
              .height(48)
              .borderRadius(8)
              .backgroundColor(this.cpMatch() ? this.cpFieldTint() : this.card())

              Text(this.tr('工作原理') + '?')
                .fontSize(14)
                .lineHeight(20)
                .fontColor(this.primary())
                .decoration({ type: TextDecorationType.Underline })
                .margin({ top: 16 })
                .onClick(() => {
                  this.openUrl('https://ente.com/architecture');
                })

              if (this.cpError.length > 0) {
                Text(this.cpError)
                  .fontSize(12)
                  .fontColor('#F53434')
                  .width('100%')
                  .margin({ top: 12 })
              }

              Blank()
            }
            .width('100%')
            .padding(20)
            .alignItems(HorizontalAlign.Start)
          }
          .width('100%')
          .layoutWeight(1)
          .align(Alignment.Top)
          .scrollBar(BarState.Off)
          .edgeEffect(EdgeEffect.Spring)

          // 官方 DynamicFAB：表单有效才可点，居中悬浮胶囊按钮
          Button() {
            if (this.cpBusy) {
              LoadingProgress()
                .width(20)
                .height(20)
                .color('#FFFFFF')
            } else {
              Text(this.tr('修改密码'))
                .fontSize(15)
                .fontWeight(FontWeight.Medium)
                .fontColor(this.cpFormValid() ? Color.White : this.faint())
            }
          }
          .height(48)
          .width('80%')
          .constraintSize({ maxWidth: 420 })
          .margin({ bottom: 24 })
          .borderRadius(24)
          .backgroundColor(this.cpFormValid() ? this.primary() : this.chipBg())
          .enabled(this.cpFormValid() && !this.cpBusy)
          .onClick(() => {
            this.cpStartChange();
          })
        }
        .width('100%')
        .height('100%')
        .backgroundColor(this.bg())

        // 官方 logOutFromOtherDevices 底部弹层
        if (this.cpLogOutSheetOpen) {
          Column()
            .width('100%')
            .height('100%')
            .backgroundColor('#88000000')
            .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
            .onClick(() => {
              this.cpLogOutSheetOpen = false;
            })
            .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
          Column() {
            this.cpLogOutSheet()
          }
          .width('100%')
          .height('100%')
          .justifyContent(FlexAlign.End)
          .padding({ bottom: 12 })
          .hitTestBehavior(HitTestMode.Transparent)
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
        }
      }
      .width('100%')
      .height('100%')
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  // "退出其他设备"弹层内容（官方 signOutFromOtherDevices sheet）
  @Builder
  cpLogOutSheet() {
    Column() {
      Text(this.tr('退出其他设备'))
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .fontColor(this.textColor())
        .width('100%')
      Text(this.tr('如果您认为有人可能知道您的密码，可以强制退出所有使用您账户的其他设备。'))
        .fontSize(14)
        .fontColor(this.muted())
        .width('100%')
        .margin({ top: 16 })
        .lineHeight(21)
      Button(this.tr('不要退出登录'))
        .width('100%')
        .height(48)
        .margin({ top: 20 })
        .borderRadius(12)
        .backgroundColor(this.primary())
        .fontColor(Color.White)
        .onClick(() => {
          this.cpLogOutSheetOpen = false;
          this.submitChangePassword(false);
        })
      Text(this.tr('退出其他设备'))
        .fontSize(14)
        .fontWeight(FontWeight.Bold)
        .fontColor('#F63A3A')
        .decoration({ type: TextDecorationType.Underline })
        .margin({ top: 20 })
        .onClick(() => {
          this.cpLogOutSheetOpen = false;
          this.submitChangePassword(true);
        })
    }
    .width('94%')
    .constraintSize({ maxWidth: 560 })
    .padding(16)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 320 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  dataPage() {
    NavDestination() {
      Column() {
        this.pageHeader('数据')
        Scroll() {
        Column() {
          Column() {
            this.navRow($r('sys.symbol.square_and_arrow_down'), '导入代码', '', false, () => {
              this.openPage('import');
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.ohos_arrow_up'), '导出代码', '', false, () => {
              this.openExport();
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.doc_plaintext'), '重复代码', '', false, () => {
              this.openDuplicates();
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.externaldrive'), '本地备份',
              '',
              false, () => {
                this.openPage('backup');
              })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.trash'), '回收站', '', false, () => {
              this.openPage('trash');
            })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)

          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  securityPage() {
    NavDestination() {
      Column() {
        this.pageHeader('安全')
        Scroll() {
        Column() {
          Column() {
            this.toggleRow($r('sys.symbol.envelope'), '电子邮件验证',
              '', this.emailMfaEnabled, (v: boolean) => {
                this.onEmailMfaToggle(v);
              })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.key'), '通行密钥', '', false, () => {
              this.openPasskeys();
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.phone'), '活跃会话', '', false, () => {
              this.requireAuth(() => {
                this.openSessions();
              });
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.lock'), '应用锁',
              '', false, () => {
                this.openPage('lock');
              })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)

          // 脚注与行内副标题二选一：放卡片下方可保持所有行高一致
          Text(this.tr('说明：鸿蒙系统暂未支持通行密钥所需的 WebAuthn 标准。若开启通行密钥，本机登录时需复制验证链接到其他设备完成验证，无法独立登录。'))
            .fontSize(11)
            .lineHeight(16)
            .fontColor(this.faint())
            .width('100%')
            .padding({ top: 8, left: 4, right: 4 })

          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  importPage() {
    NavDestination() {
      Column() {
        this.pageHeader('导入代码')
        Scroll() {
          Column() {
            Column() {
              this.navRow($r('sys.symbol.doc_plaintext'), '纯文本', '', false, () => {
                this.importGuideApp = 'plain';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.lock'), 'Ente 加密导出', '', false, () => {
                this.importGuideApp = 'ente';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), '2FAS Authenticator', '', false, () => {
                this.importGuideApp = '2fas';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'Aegis Authenticator', '', false, () => {
                this.importGuideApp = 'aegis';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'andOTP', '', false, () => {
                this.importGuideApp = 'andotp';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'Open Authenticator', '', false, () => {
                this.importGuideApp = 'openauth';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'Bitwarden', '', false, () => {
                this.importGuideApp = 'bitwarden';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.qrcode'), 'Google Authenticator', '', false, () => {
                this.importGuideApp = 'ga';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'Proton Authenticator', '', false, () => {
                this.importGuideApp = 'proton';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'Raivo OTP', '', false, () => {
                this.importGuideApp = 'raivo';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'LastPass Authenticator', '', false, () => {
                this.importGuideApp = 'lastpass';
              })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), 'OTP Auth', '', false, () => {
                this.importGuideApp = 'otpauth';
              })
            }
            .width('100%')
            .backgroundColor(this.card())
            .borderRadius(12)
          }
          .width('100%')
          .padding(20)
          .alignItems(HorizontalAlign.Start)
        }
        .layoutWeight(1)
        .scrollBar(BarState.Off)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  backupPage() {
    NavDestination() {
      Column() {
        this.pageHeader('本地备份')
        Scroll() {
        Column() {
          // 对齐官方：自动备份开关独立分组
          Column() {
            this.toggleRow($r('sys.symbol.lock'), '自动备份',
              '', this.backupOn,
              (v: boolean) => {
                this.setBackupOn(v);
              })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)

          Text(this.tr('每天打开应用时会创建一份本地备份。使用“立即备份”可手动执行备份。最多保留 5 个备份。'))
            .fontSize(11)
            .fontColor(this.muted())
            .lineHeight(17)
            .margin({ top: 8 })

          // 对齐官方：开启自动备份后展示密码与立即备份菜单组
          if (this.backupOn) {
            Column() {
              this.navRow($r('sys.symbol.key'), this.backupPwdSet ? '更新备份密码' : '设置备份密码',
                '', false, () => {
                  this.backupOpenPwdSheet();
                })
              Divider().color(this.divider())
              this.navRow($r('sys.symbol.externaldrive'), '立即创建备份', '', false, () => {
                this.runBackup(false);
              })
            }
            .width('100%')
            .backgroundColor(this.card())
            .borderRadius(12)
            .margin({ top: 16 })

            Text(this.tr('备份文件夹：') + this.backupPath)
              .fontSize(11)
              .fontColor(this.faint())
              .lineHeight(16)
              .margin({ top: 6 })
              .maxLines(2)
          }
          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  lockDelayRow(title: string, v: number) {
    Row() {
      Text(this.tr(title))
        .fontSize(15)
        .fontColor(this.textColor())
        .layoutWeight(1)
      SymbolGlyph($r('sys.symbol.checkmark'))
        .fontSize(16)
        .fontColor([this.primary()])
        .opacity(this.lockDelay === v ? 1 : 0)
    }
    .width('100%')
    .height(52)
    .padding({ left: 14, right: 14 })
    .onClick(() => {
      this.setLockDelay(v);
    })
  }

  @Builder
  lockPage() {
    NavDestination() {
      Column() {
        this.pageHeader('应用锁')
        Scroll() {
        Column() {
          Column() {
            this.toggleRow($r('sys.symbol.lock'), '应用锁', '', this.appLock,
              (v: boolean) => {
                this.setAppLock(v);
              })
            Divider().color(this.divider())
            this.lockDelayRow('立即', 0)
            Divider().color(this.divider())
            this.lockDelayRow('1 分钟', 1)
            Divider().color(this.divider())
            this.lockDelayRow('5 分钟', 5)
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)

          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  themePage() {
    NavDestination() {
      Column() {
        this.pageHeader('主题')
        Scroll() {
        Column() {
          Column() {
            this.themeRow($r('sys.symbol.circle_lefthalf_inset_filled'), '跟随系统', THEME_SYSTEM, () => {
              this.setTheme(THEME_SYSTEM);
            })
            Divider().color(this.divider())
            this.themeRow($r('sys.symbol.sun_max'), '浅色', THEME_LIGHT, () => {
              this.setTheme(THEME_LIGHT);
            })
            Divider().color(this.divider())
            this.themeRow($r('sys.symbol.moon'), '深色', THEME_DARK, () => {
              this.setTheme(THEME_DARK);
            })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)

          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  languageSheet() {
    Column() {
      Row() {
        Text(this.tr('语言'))
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.textColor())
          .layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          SymbolGlyph($r('sys.symbol.xmark'))
            .fontSize(16)
            .fontColor([this.textColor()])
        }
        .width(32)
        .height(32)
        .backgroundColor(Color.Transparent)
        .onClick(() => {
          this.languageOpen = false;
        })
      }
      .width('100%')

      List() {
        ForEach(LOCALE_CODES, (code: string) => {
          ListItem() {
            Row() {
              Text(this.localeName(code))
                .fontSize(16)
                .fontColor(this.textColor())
                .layoutWeight(1)
              if (this.locale === code) {
                SymbolGlyph($r('sys.symbol.checkmark'))
                  .fontSize(18)
                  .fontColor([this.primary()])
              }
            }
            .width('100%')
            .height(48)
            .padding({ left: 8, right: 8 })
            .onClick(() => {
              this.setLocale(code);
              this.languageOpen = false;
              // 重建当前二级页，保证文案随语言立即刷新
              this.refreshCurrentPage();
            })
          }
        }, (code: string) => code)
      }
      .width('100%')
      .layoutWeight(1)
      .margin({ top: 8 })
      .divider({ strokeWidth: 0.5, color: this.divider() })
    }
    .width('94%')
    // 旋转适配：横屏/平板下弹层限宽，避免铺满整屏
    .constraintSize({ maxWidth: 560 })
    .height('64%')
    .padding(20)
    .backgroundColor(this.elevated())
    .borderRadius(16)
    .attributeModifier(this.matColRegular)
    .transition(TransitionEffect.translate({ y: 420 }).combine(TransitionEffect.OPACITY)
      .animation({ duration: 260, curve: Curve.Friction }))
  }

  @Builder
  generalPage() {
    NavDestination() {
      Column() {
        this.pageHeader('通用')
        Scroll() {
        Column() {
          Column() {
            this.navRow($r('sys.symbol.translate'), '语言', this.localeName(this.locale), false, () => {
              this.languageOpen = true;
            })
            Divider().color(this.divider())
            this.toggleRow($r('sys.symbol.gearshape'), '显示大图标', '', this.bigIcons,
              (v: boolean) => {
                this.setBigIcons(v);
              })
            Divider().color(this.divider())
            this.toggleRow($r('sys.symbol.list_bullet'), '紧凑模式', '', this.compact,
              (v: boolean) => {
                this.setCompact(v);
              })
            Divider().color(this.divider())
            this.toggleRow($r('sys.symbol.eye_slash'), '隐藏代码', '', this.hideCodes,
              (v: boolean) => {
                this.setHideCodes(v);
              })
            Divider().color(this.divider())
            this.toggleRow($r('sys.symbol.checkmark_clipboard'), '复制时最小化应用', '', this.copyMinimize,
              (v: boolean) => {
                this.setCopyMinimize(v);
              })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)
          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  trashPage() {
    NavDestination() {
      Column() {
        this.pageHeader('回收站')
        if (this.trashRows().length === 0) {
          Column() {
            SymbolGlyph($r('sys.symbol.trash'))
              .fontSize(40)
              .fontColor([this.faint()])
            Text(this.tr('回收站为空'))
              .fontSize(16)
              .fontColor(this.muted())
              .margin({ top: 12 })
          }
          .width('100%')
          .layoutWeight(1)
          .justifyContent(FlexAlign.Center)
        } else {
          List() {
            ForEach(this.trashRows(), (r: OtpRow) => {
              this.codeCard(r);
            }, (r: OtpRow) => r.id + ':' + r.step)
          }
          .width('100%')
          .layoutWeight(1)
          .padding({ left: 16, right: 16, top: 8 })
          .scrollBar(BarState.Off)
          .edgeEffect(EdgeEffect.Spring)
        }
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  // 对齐官方 DuplicateCodePage：分组勾选 + 全选 + 移入回收站（需验证并二次确认）
  @Builder
  duplicatesPage() {
    NavDestination() {
      Column() {
        this.pageHeader('删除重复代码')
        Scroll() {
          Column() {
            Row() {
              Blank()
              Button(this.dupSelKeys.length === this.dupGroupList().length ? this.tr('取消全选') : this.tr('全选'))
                .fontSize(13)
                .height(32)
                .padding({ left: 14, right: 14 })
                .backgroundColor(this.chipBg())
                .fontColor(this.textColor())
                .onClick(() => {
                  this.toggleDupAll();
                })
            }
            .width('100%')
            .margin({ bottom: 10 })

            ForEach(this.dupGroupList(), (g: OtpRow[]) => {
              Column() {
                Row() {
                  Text(this.titleOf(g[0]) + ' (' + g.length.toString() + ')')
                    .fontSize(15)
                    .fontWeight(FontWeight.Medium)
                    .fontColor(this.textColor())
                    .layoutWeight(1)
                  Checkbox()
                    .select(this.dupSelKeys.indexOf(g[0].id) >= 0)
                    .selectedColor(this.primary())
                    .onChange((v: boolean) => {
                      this.toggleDupGroup(g);
                    })
                }
                .width('100%')
                .padding(14)
                .onClick(() => {
                  this.toggleDupGroup(g);
                })

                ForEach(g, (r: OtpRow) => {
                  Column() {
                    Text(this.titleOf(r))
                      .fontSize(14)
                      .fontColor(this.textColor())
                    Text(r.account.length > 0 ? r.account : this.formatCode(r.code))
                      .fontSize(11)
                      .fontColor(this.muted())
                      .margin({ top: 3 })
                  }
                  .width('100%')
                  .alignItems(HorizontalAlign.Start)
                  .padding({ left: 14, right: 14, top: 8, bottom: 8 })
                }, (r: OtpRow) => r.id)
              }
              .width('100%')
              .backgroundColor(this.card())
              .borderRadius(8)
              .margin({ bottom: 10 })
            }, (g: OtpRow[]) => g[0].id)

            if (this.dupSelectedExtras() > 0) {
              Button(this.tr('回收站') + ' (' + this.dupSelectedExtras().toString() + ')')
                .width('100%')
                .height(44)
                .margin({ top: 8 })
                .backgroundColor(this.orange())
                .onClick(() => {
                  // 对齐官方：删除重复代码需本地身份验证后二次确认
                  this.requireAuth(() => {
                    this.dupConfirmOpen = true;
                  });
                })
            }
          }
          .width('100%')
          .padding(20)
          .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  @Builder
  supportPage() {
    NavDestination() {
      Column() {
        this.pageHeader('支持')
        Scroll() {
        Column() {
          Column() {
            this.navRow($r('sys.symbol.questionmark_circle'), '常见问题', '', false, () => {
              this.openUrl('https://ente.com/help/auth/faq');
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.lightbulb'), '建议新功能', '', false, () => {
              this.openUrl('https://github.com/ente-io/ente/discussions');
            })
            Divider().color(this.divider())
            this.navRow($r('sys.symbol.exclamationmark_message'), '报告问题', '', false, () => {
              this.copySupportEmail();
            })
          }
          .width('100%')
          .backgroundColor(this.card())
          .borderRadius(12)
          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  private async copySupportEmail(): Promise<void> {
    try {
      const data: pasteboard.PasteData = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, 'auth@ente.com');
      await pasteboard.getSystemPasteboard().setData(data);
      this.toast(this.tr('已复制到剪贴板'));
    } catch (e) {
      hilog.error(0x0000, TAG, 'copy support email failed: %{public}s', (e as Error).message);
    }
  }


  @Builder
  qrPage() {
    NavDestination() {
      Column() {
        this.pageHeader('二维码')
        Scroll() {
        Column() {
          Text(this.qrTitle)
            .fontSize(18)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.textColor())
          QRCode(this.qrUri)
            .width(220)
            .height(220)
            .color('#000000')
            .backgroundColor('#FFFFFF')
            .margin({ top: 24 })
          Text(this.tr('请使用您的身份验证器应用\n扫描此条码'))
            .fontSize(12)
            .fontColor(this.muted())
            .margin({ top: 16 })
          Text(this.qrUri)
            .fontSize(10)
            .fontColor(this.faint())
            .maxLines(2)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .margin({ top: 16 })
            .padding(10)
            .width('100%')
            .backgroundColor(this.card())
            .borderRadius(6)
          Button(this.tr('复制链接'))
            .height(44)
            .width('100%')
            .margin({ top: 16 })
            .backgroundColor(this.primary())
            .onClick(async () => {
              try {
                const data: pasteboard.PasteData =
                  pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, this.qrUri);
                await pasteboard.getSystemPasteboard().setData(data);
                this.toast(this.tr('已复制到剪贴板'));
              } catch (e) {
                hilog.error(0x0000, TAG, 'copy qr link failed: %{public}s', (e as Error).message);
              }
            })
          Blank()
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Center)
        }
        .layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Off)
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.bg())
    }
    .hideTitleBar(true)
    .backgroundColor(this.bg())
  }

  build() {
    Stack() {
      if (this.scriptsReady && this.privacyReady && this.privacyAccepted) {
        Web({ src: START_URL, controller: this.controller })
          .javaScriptAccess(true)
          .domStorageAccess(true)
          .databaseAccess(true)
          .fileAccess(true)
          .zoomAccess(true)
          .javaScriptOnDocumentStart(this.scripts)
          .onInterceptRequest((event: OnInterceptRequestEvent) => this.interceptRequest(event))
          // 登录态隐藏的 Web 不能进入 Tab 焦点环：否则连按 Tab 焦点落入网页输入框，
          // 其渲染面被提升到原生登录层之上，表现为注册/登录界面来回翻转
          .focusable(this.webPageOpen)
          .visibility((this.mode === 'ready' && !this.webPageOpen && !this.webLoading) ?
            Visibility.None : Visibility.Visible)
          .onPageEnd(() => {
            // 错误页也会触发 onPageEnd，需结合 onErrorReceive 判定是否真正加载成功
            this.webReady = !this.loadFailed;
            this.loadFailed = false;
            let endedUrl: string = '';
            try {
              endedUrl = this.controller.getUrl();
            } catch (e) {
              // WebView 尚未就绪时 getUrl 可能抛错，忽略
            }
            hilog.info(0x0000, TAG, 'page loaded url=%{public}s ready=%{public}s',
              endedUrl, this.webReady.toString());
            // Web 从 None 切回 Visible 时底层可能重建并重载 src（START_URL，引擎页），
            // 打断刚发出的外部账户页导航（表现为紫屏）。落点不对时重载目标页，
            // 加载圈（webLoading）保持覆盖直到目标页真正加载完成。
            if (this.webPageOpen && this.webTargetBase.length > 0) {
              if (endedUrl.length > 0 && endedUrl.indexOf(this.webTargetBase) !== 0) {
                hilog.info(0x0000, TAG, 'web nav clobbered, retry: %{public}s', this.webTargetUrl);
                try {
                  this.controller.loadUrl(this.webTargetUrl);
                } catch (e) {
                  // 页面未就绪时忽略，等待下次 onPageEnd 重试
                }
                return;
              }
              this.webTargetUrl = '';
              this.webTargetBase = '';
            }
            // 账户页 / 登录页已经呈现，撤掉原生加载圈，交还给 WebView
            if (this.webLoading && (this.webPageOpen || this.mode !== 'ready')) {
              this.webLoading = false;
            }
            // 启动/登出后一直显示启动图，页面就绪后再切换：
            // 会话存在即已登录，进列表层（空库显示占位），不再按行数误跳登录层
            if (this.webReady && this.mode === 'boot') {
              const hasSess: boolean = this.store !== null && this.store.get(KEY_SESSION).length > 0;
              this.mode = (this.bioOk && hasSess) ? 'ready' : 'login';
            }
            if (this.webPageOpen) {
              this.repairWebKv();
            }
          })
          .onErrorReceive((event) => {
            if (event && event.request.isMainFrame()) {
              this.loadFailed = true;
              this.webReady = false;
              this.webLoading = false;
              this.nextReloadAt = Date.now() + 5000;
              if (this.rows.length > 0 && this.mode !== 'ready') {
                this.mode = 'ready';
                this.notice = this.tr('网络不可用，显示离线缓存');
              }
              hilog.error(0x0000, TAG, 'load error: %{public}s', event.request.getRequestUrl());
            }
          })
      }

      if (this.bioOk && this.mode === 'ready') {
        // 原生导航栈：设置里的二级页面入栈，标题栏自动带返回
        Navigation(this.pathStack) {
          this.nativeBody()
        }
        .mode(NavigationMode.Stack)
        .hideTitleBar(true)
        .navDestination(this.pageMap)
        .width('100%')
        .height('100%')
        // 横屏时让出摄像头挖孔，避免二级页面内容与挖孔交叉
        .padding({ left: this.safeL, right: this.safeR })
        // 应用内官方网页打开时仅隐藏不卸载：保留导航栈与页面状态，
        // 关闭网页后原页面（如安全页）原样恢复，不重放转场动画
        .visibility(this.webPageOpen ? Visibility.None : Visibility.Visible)
      }

      // 应用内官方页面：左上角原生返回，页面本身仍是同一 WebView（保留登录态）
      if (this.webPageOpen) {
        Column() {
          Row() {
            Button({ type: ButtonType.Circle }) {
              SymbolGlyph($r('sys.symbol.xmark'))
                .fontSize(18)
                .fontColor([this.textColor()])
            }
            .width(38)
            .height(38)
            .backgroundColor(this.elevated())
            .shadow({ radius: 8, color: '#22000000', offsetX: 0, offsetY: 2 })
            .onClick(() => {
              this.closeWebAccountPage();
            })
            Text(this.webPageTitle)
              .fontSize(14)
              .fontColor(this.textColor())
              .margin({ left: 10 })
              .padding({ left: 10, right: 10, top: 6, bottom: 6 })
              .backgroundColor(this.elevated())
              .borderRadius(10)
          }
          .width('100%')
          .padding({ left: 12, right: 12, top: this.topInset + 8 })
        }
        .width('100%')
        .height('100%')
        .alignItems(HorizontalAlign.Start)
        .hitTestBehavior(HitTestMode.Transparent)
      }

      // 原生分步登录层：位于隐藏 WebView 之上、启动图与同步加载圈之下
      if (this.mode === 'login' && this.scriptsReady) {
        Column() {
          this.loginView()
        }
        .width('100%')
        .height('100%')
        .backgroundColor(this.bg())
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 冷启动等待 webview 加载期间显示中性加载圈（无紫色启动图），不遮挡已有缓存的原生列表
      if (this.mode === 'boot' || (!this.scriptsReady && this.mode !== 'ready')) {
        Column() {
          LoadingProgress()
            .width(40)
            .height(40)
            .color(this.muted())
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor(this.bg())
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 账户页请求校验/加载期间：隐藏网页内容，只显示原生紫色加载圈（与官方一致）
      if (this.webLoading) {
        Column() {
          LoadingProgress()
            .width(40)
            .height(40)
            .color(this.primary())
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor(this.bg())
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (!this.bioOk) {
        Column() {
          Text(this.tr('请验证'))
            .fontSize(14)
            .fontColor(this.textColor())
          Button(this.tr('验证'))
            .margin({ top: 16 })
            .backgroundColor(this.primary())
            .onClick(async () => {
              this.bioOk = await Biometrics.verify(this.tr('请验证'));
            })
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .backgroundColor(this.bg())
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.sortOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.sortOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.sortCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.menuId.length > 0 && this.menuConfirm) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.menuConfirm = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.confirmCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.menuId.length > 0 && !this.menuConfirm) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.menuId = '';
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.menuCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.selectionMode && !this.tagOpen) {
        Column() {
          this.selectionSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.tagOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.tagOpen = false;
            this.tagInput = '';
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.tagCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.selDeleteConfirm) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.selDeleteConfirm = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.selDeleteCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.noteOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.noteOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.noteCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.emailOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.emailOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.emailSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.recoveryOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.recoveryOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.recoverySheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.emailMfaWarnOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.emailMfaWarnOpen = false;
            this.emailMfaEnabled = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.emailMfaWarnSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.sessionsOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.sessionsOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.sessionsSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.exportOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.exportOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.exportSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.importPwdOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.importPwdOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.importPwdSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 导入说明弹层（对齐官方 instruction sheet）
      if (this.importGuideApp.length > 0) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.importGuideApp = '';
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.importGuideSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 导入成功弹层（对齐官方 importSuccessDialog）
      if (this.importSuccessCount >= 0) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.importSuccessSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 无重复代码提示（对齐官方对话框）
      if (this.noDupOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.noDupOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.noDupCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 删除重复项二次确认弹层
      if (this.dupConfirmOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.dupConfirmOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.dupConfirmSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.languageOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.languageOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.languageSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.backupPwdOpen) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.backupPwdOpen = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.backupPwdSheet()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.End)
        .padding({ bottom: 12 })
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      if (this.logoutConfirm) {
        Column()
          .width('100%')
          .height('100%')
          .backgroundColor('#88000000')
          .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
          .onClick(() => {
            this.logoutConfirm = false;
          })
          .transition(TransitionEffect.OPACITY.animation({ duration: 200 }))
        Column() {
          this.logoutCard()
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .hitTestBehavior(HitTestMode.Transparent)
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }

      // 首次启动隐私合规页：未同意前不渲染 WebView，也不发起任何网络请求
      if (this.privacyReady && !this.privacyAccepted) {
        Column() {
          Column() {
            Text(this.tr('隐私政策与用户协议'))
              .fontSize(21)
              .fontWeight(FontWeight.Bold)
              .fontColor(this.textColor())
              .width('100%')
            Text(this.tr('请阅读并同意以下条款后再开始使用。'))
              .fontSize(13)
              .fontColor(this.muted())
              .width('100%')
              .margin({ top: 6 })

            Scroll() {
              Column() {
                Text(this.tr('本应用是社区维护的鸿蒙客户端，基于 Ente Auth 开源项目（AGPL-3.0）构建，并非 Ente 官方发布。'))
                  .fontSize(14)
                  .lineHeight(21)
                  .fontColor(this.muted())
                  .width('100%')
                Text(this.tr('验证码、备注与登录凭据仅以加密形式保存在本机；登录令牌只用于与 Ente 服务器同步你的加密数据。'))
                  .fontSize(14)
                  .lineHeight(21)
                  .fontColor(this.muted())
                  .width('100%')
                  .margin({ top: 10 })
                Text(this.tr('应用不含广告、统计或追踪 SDK，不会收集设备信息用于画像，也不会向任何第三方出售或共享你的数据。'))
                  .fontSize(14)
                  .lineHeight(21)
                  .fontColor(this.muted())
                  .width('100%')
                  .margin({ top: 10 })
                Text(this.tr('相机权限仅在你主动扫码时使用；生物识别在本机完成，指纹与人脸数据不会离开设备。'))
                  .fontSize(14)
                  .lineHeight(21)
                  .fontColor(this.muted())
                  .width('100%')
                  .margin({ top: 10 })
                Text(this.tr('你可以随时在设置中退出登录、删除账户，或在系统设置中清除本应用数据。'))
                  .fontSize(14)
                  .lineHeight(21)
                  .fontColor(this.muted())
                  .width('100%')
                  .margin({ top: 10 })
              }
              .width('100%')
              .alignItems(HorizontalAlign.Start)
            }
            .width('100%')
            .layoutWeight(1)
            .scrollBar(BarState.Off)
            .margin({ top: 14 })

            Row() {
              Text(this.tr('隐私政策'))
                .fontSize(14)
                .fontColor(this.primary())
                .decoration({ type: TextDecorationType.Underline, color: this.primary() })
                .onClick(() => {
                  this.openUrl(PRIVACY_URL);
                })
              Text(this.tr('用户协议'))
                .fontSize(14)
                .fontColor(this.primary())
                .decoration({ type: TextDecorationType.Underline, color: this.primary() })
                .margin({ left: 20 })
                .onClick(() => {
                  this.openUrl(TERMS_URL);
                })
            }
            .width('100%')
            .margin({ top: 12 })

            Button(this.tr('同意并继续'))
              .width('100%')
              .height(46)
              .backgroundColor(this.primary())
              .fontColor('#FFFFFF')
              .fontSize(15)
              .margin({ top: 16 })
              .onClick(() => {
                this.acceptPrivacy();
              })

            Button(this.tr('不同意并退出'))
              .width('100%')
              .height(46)
              .backgroundColor(Color.Transparent)
              .fontColor(this.muted())
              .fontSize(15)
              .border({ width: 1, color: this.divider() })
              .margin({ top: 8 })
              .onClick(() => {
                this.exitApp();
              })
          }
          .width('100%')
          .height('86%')
          .padding({ left: 20, right: 20, top: 24, bottom: 20 })
          .backgroundColor(this.elevated())
          .borderRadius(20)
        }
        .width('100%')
        .height('100%')
        .padding({ left: 16, right: 16, top: this.topInset, bottom: this.safeB })
        .justifyContent(FlexAlign.Center)
        .backgroundColor(this.bg())
        .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
      }
    }
    .width('100%')
    .height('100%')
    // 旋转适配：记录窗口尺寸（vp），横屏时限制内容列与抽屉宽度
    .onAreaChange((oldV: Area, newV: Area) => {
      const w: number = Number(newV.width);
      const h: number = Number(newV.height);
      if (w > 0 && h > 0 && (Math.abs(w - this.rootW) > 0.5 || Math.abs(h - this.rootH) > 0.5)) {
        // 宽度变化 = 旋转/折叠/窗口缩放：重置稳定高度；键盘 RESIZE 只压高度，取历史最大值
        const rotated = Math.abs(w - this.rootW) > 0.5;
        this.rootW = w;
        this.rootH = h;
        // 稳定高度直接取物理屏幕尺寸（px2vp），不受键盘 RESIZE 压缩影响，杜绝冷启动
        // auto-focus 弹键盘时首次回调拿到压缩高度的污染；部分真机 display 宽高不随
        // 旋转交换（恒为自然方向），用不受键盘影响的窗口宽 w 匹配 display 同轴，
        // 取另一轴作为无键盘稳定高度；display 不可用时回退到旋转重置 + 历史最大值
        let stableFromDisp = 0;
        try {
          const d: display.Display = display.getDefaultDisplaySync();
          const dw: number = px2vp(d.width);
          const dh: number = px2vp(d.height);
          if (dw > 0 && dh > 0) {
            stableFromDisp = Math.abs(dw - w) <= Math.abs(dh - w) ? dh : dw;
          }
        } catch (e) {
          stableFromDisp = 0;
        }
        this.stableH = stableFromDisp > 0 ? stableFromDisp : (rotated ? h : Math.max(this.stableH, h));
        this.landscape = w > h;
        // 旋转后重新读取安全区（横屏时摄像头挖孔会落在左右两侧）
        this.refreshInsets();
      }
    })
  }
}

// ---------- otpauth URI 解析（扫码/导入用） ----------

function parseOtpUri(uri: string): OtpRow | null {
  const t: string = uri.trim();
  if (t.indexOf('otpauth://') !== 0) return null;
  const q: number = t.indexOf('?');
  const base: string = q < 0 ? t : t.slice(0, q);
  const qs: string = q < 0 ? '' : t.slice(q + 1);

  const keys: string[] = [];
  const vals: string[] = [];
  for (const kv of qs.split('&')) {
    if (kv.length === 0) continue;
    const i: number = kv.indexOf('=');
    const k: string = i < 0 ? kv : kv.slice(0, i);
    let v: string = i < 0 ? '' : kv.slice(i + 1);
    try {
      v = decodeURIComponent(v);
    } catch (e) {
      // 保留原始值
    }
    keys.push(k);
    vals.push(v);
  }

  const get = (key: string): string => {
    for (let i = 0; i < keys.length; i++) {
      if (keys[i] === key) return vals[i];
    }
    return '';
  };

  const rest: string = base.substring('otpauth://'.length);
  const slash: number = rest.indexOf('/');
  const type: string = slash < 0 ? rest : rest.substring(0, slash);
  let label: string = slash < 0 ? '' : rest.substring(slash + 1);
  try {
    label = decodeURIComponent(label);
  } catch (e) {
    // 保留原始值
  }

  let issuer: string = get('issuer');
  if (issuer.indexOf('period=') >= 0) issuer = issuer.substring(0, issuer.indexOf('period='));
  let account: string = label;
  if (issuer.length > 0) {
    if (label.indexOf(issuer + ':') === 0) account = label.substring(issuer.length + 1);
  } else {
    const c: number = label.indexOf(':');
    if (c >= 0) {
      issuer = label.substring(0, c);
      account = label.substring(c + 1);
    }
  }

  const secret: string = get('secret').replace(/\s+/g, '').toUpperCase();
  if (secret.length === 0) return null;

  let digits: number = parseInt(get('digits'), 10);
  if (isNaN(digits)) digits = type === 'steam' ? 5 : 6;
  let period: number = parseInt(get('period'), 10);
  if (isNaN(period)) period = 30;
  let algorithm: string = get('algorithm').toLowerCase();
  if (algorithm !== 'sha256' && algorithm !== 'sha512') algorithm = 'sha1';

  const row: OtpRow = new OtpRow();
  row.type = type;
  row.issuer = issuer;
  row.account = account;
  row.secret = secret;
  row.digits = digits;
  row.period = period;
  row.algorithm = algorithm;
  return row;
}

function htmlEsc(s: string): string {
  return s.split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;')
    .split('"').join('&quot;');
}

// RFC 4648 Base32（无填充）
function base32Encode(bytes: Uint8Array): string {
  const alpha: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let acc: number = 0;
  let bits: number = 0;
  let out: string = '';
  for (let i = 0; i < bytes.length; i++) {
    acc = (acc << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alpha.charAt((acc >>> (bits - 5)) & 31);
      bits -= 5;
    }
    acc = acc & ((1 << bits) - 1);
  }
  if (bits > 0) out += alpha.charAt((acc << (5 - bits)) & 31);
  return out;
}

class PbCursor {
  pos: number = 0;
}

function pbVarint(b: Uint8Array, c: PbCursor): number {
  let result: number = 0;
  let shift: number = 0;
  while (c.pos < b.length) {
    const byte: number = b[c.pos];
    c.pos++;
    result += (byte & 0x7f) * Math.pow(2, shift);
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 35) break;
  }
  return result;
}

// Google Authenticator 迁移载荷中的单条 OtpParameters
function parseOtpParameters(b: Uint8Array): OtpRow | null {
  let secret: Uint8Array = new Uint8Array(0);
  let name: string = '';
  let issuer: string = '';
  let alg: number = 0;
  let digits: number = 0;
  let kind: number = 0;
  const decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
  const c: PbCursor = new PbCursor();
  while (c.pos < b.length) {
    const tag: number = pbVarint(b, c);
    const field: number = Math.floor(tag / 8);
    const wire: number = tag % 8;
    if (wire === 0) {
      const v: number = pbVarint(b, c);
      if (field === 4) alg = v;
      else if (field === 5) digits = v;
      else if (field === 6) kind = v;
    } else if (wire === 2) {
      const len: number = pbVarint(b, c);
      const start: number = c.pos;
      const end: number = Math.min(start + len, b.length);
      c.pos = end;
      if (field === 1) {
        secret = b.subarray(start, end);
      } else if (field === 2) {
        name = decoder.decodeToString(b.subarray(start, end));
      } else if (field === 3) {
        issuer = decoder.decodeToString(b.subarray(start, end));
      }
    } else if (wire === 1) {
      c.pos += 8;
    } else if (wire === 5) {
      c.pos += 4;
    } else {
      break;
    }
  }
  if (secret.length === 0) return null;
  const row: OtpRow = new OtpRow();
  row.type = kind === 1 ? 'hotp' : 'totp';
  row.issuer = issuer;
  row.account = name;
  row.secret = base32Encode(secret);
  row.digits = digits === 1 ? 8 : 6;
  row.period = 30;
  row.algorithm = alg === 1 ? 'sha256' : (alg === 2 ? 'sha512' : 'sha1');
  return row;
}

// 解析 otpauth-migration://offline?data=...
function parseMigrationUri(uri: string): OtpRow[] {
  const out: OtpRow[] = [];
  const q: number = uri.indexOf('?');
  if (q < 0) return out;
  let data: string = '';
  for (const kv of uri.substring(q + 1).split('&')) {
    if (kv.indexOf('data=') === 0) data = kv.substring(5);
  }
  if (data.length === 0) return out;
  try {
    data = decodeURIComponent(data);
  } catch (e) {
    // 保留原始内容
  }
  let bytes: Uint8Array;
  try {
    bytes = new util.Base64Helper().decodeSync(data);
  } catch (e) {
    return out;
  }
  const c: PbCursor = new PbCursor();
  while (c.pos < bytes.length) {
    const tag: number = pbVarint(bytes, c);
    const field: number = Math.floor(tag / 8);
    const wire: number = tag % 8;
    if (wire === 0) {
      pbVarint(bytes, c);
    } else if (wire === 1) {
      c.pos += 8;
    } else if (wire === 5) {
      c.pos += 4;
    } else if (wire === 2) {
      const len: number = pbVarint(bytes, c);
      const start: number = c.pos;
      const end: number = Math.min(start + len, bytes.length);
      c.pos = end;
      if (field === 1) {
        const row: OtpRow | null = parseOtpParameters(bytes.subarray(start, end));
        if (row !== null) out.push(row);
      }
    } else {
      break;
    }
  }
  return out;
}
