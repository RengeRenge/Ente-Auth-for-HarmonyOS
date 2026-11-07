// 与 JS 桥 list 返回的行结构对应
export class OtpRow {
  id: string = '';
  uri: string = '';
  updatedAt: number = 0;
  issuer: string = '';
  account: string = '';
  digits: number = 6;
  period: number = 30;
  algorithm: string = 'sha1';
  type: string = 'totp';
  secret: string = '';
  counter: number = 0;
  pinned: boolean = false;
  trashed: boolean = false;
  note: string = '';
  tags: string[] = [];
  broken: boolean = false;

  // 运行态
  code: string = '';
  nextCode: string = '';
  step: number = -1;
}
