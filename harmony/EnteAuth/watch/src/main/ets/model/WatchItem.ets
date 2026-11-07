// 手表端验证码条目模型
export class WatchItem {
  id: string = '';
  issuer: string = '';
  account: string = '';
  secret: string = '';
  digits: number = 6;
  period: number = 30;
  algorithm: string = 'sha1';
  type: string = 'totp';
  pinned: boolean = false;
  // 运行态
  code: string = '';
  step: number = -1;
}

// 手机端同步过来的紧凑行（短字段名，节省 P2P 消息字节）
export interface WearRowRaw {
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
