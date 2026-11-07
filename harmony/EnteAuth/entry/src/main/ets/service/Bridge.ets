import { webview } from '@kit.ArkWeb';
import { OtpRow } from '../model/OtpRow';

export class ProbeState {
  hasSessionKey: boolean = false;
  sodiumReady: boolean = false;
  host: string = '';
  cached: number = 0;
  sessionKeys: string[] = [];
  email: string = '';
}

export class BridgeResult {
  seq: number = 0;
  op: string = '';
  ok: boolean = false;
  payload: string = '';
  error: string = '';
}

export class PollPayload {
  probe: ProbeState = new ProbeState();
  results: BridgeResult[] = [];
}

// runJavaScriptExt 的 getString 返回 JSON 字面量（带引号），还原成原字符串
export function unquote(s: string): string {
  if (s.length >= 2 && s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') {
    try {
      return JSON.parse(s) as string;
    } catch (e) {
      return s;
    }
  }
  return s;
}

export class Bridge {
  private ctrl: webview.WebviewController;
  private seq: number = 0;
  private pending: Map<number, (r: BridgeResult) => void> = new Map();

  constructor(ctrl: webview.WebviewController) {
    this.ctrl = ctrl;
  }

  exec(js: string): Promise<string> {
    return this.ctrl.runJavaScriptExt(js).then((r) => unquote(r.getString()));
  }

  poll(): Promise<PollPayload> {
    return this.exec('__enteExt.poll()').then((raw) => {
      const p: PollPayload = JSON.parse(raw) as PollPayload;
      if (p.results === undefined) p.results = [];
      if (p.probe === undefined) p.probe = new ProbeState();
      return p;
    });
  }

  // 发送命令并等待对应 seq 的结果。
  // timeoutMs：argon2 等重加密操作（loginPassword/signupFinish/unlockWithPassword 等）
  // 在低端设备上可能耗时远超 30s，由调用方显式传更长超时。
  call(op: string, argsJson: string, timeoutMs: number = 30000): Promise<BridgeResult> {
    this.seq++;
    const seq: number = this.seq;
    const json: string = '{"seq":' + seq + ',"op":"' + op + '","args":' + argsJson + '}';
    return new Promise<BridgeResult>((resolve: (r: BridgeResult) => void, reject: (e: Error) => void) => {
      let settled: boolean = false;
      const timer: number = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.pending.delete(seq);
        reject(new Error('bridge_timeout:' + op));
      }, timeoutMs);
      this.pending.set(seq, (r: BridgeResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(r);
      });
      this.exec('__enteExt.cmd(' + JSON.stringify(json) + ')').catch((e: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.pending.delete(seq);
        reject(e);
      });
    });
  }

  // 分发轮询中取到的结果
  dispatch(results: BridgeResult[]): void {
    for (let i = 0; i < results.length; i++) {
      const r: BridgeResult = results[i];
      const cb = this.pending.get(r.seq);
      if (cb !== undefined) {
        this.pending.delete(r.seq);
        cb(r);
      }
    }
  }

  hasPending(): boolean {
    return this.pending.size > 0;
  }
}

// 把 JS 返回的行 payload 转成强类型数组
export function rowsFromPayload(payload: string): OtpRow[] {
  const raw: OtpRow[] = JSON.parse(payload) as OtpRow[];
  const out: OtpRow[] = [];
  if (raw === null) return out;
  for (let i = 0; i < raw.length; i++) {
    const r: OtpRow = raw[i];
    const row: OtpRow = new OtpRow();
    row.id = r.id;
    row.uri = r.uri;
    row.updatedAt = r.updatedAt;
    row.issuer = r.issuer;
    row.account = r.account;
    row.digits = r.digits;
    row.period = r.period;
    row.algorithm = r.algorithm;
    row.type = r.type;
    row.secret = r.secret;
    row.counter = r.counter;
    row.pinned = r.pinned;
    row.trashed = r.trashed;
    row.note = r.note;
    row.tags = r.tags === undefined ? [] : r.tags;
    row.broken = r.broken === true;
    out.push(row);
  }
  return out;
}
