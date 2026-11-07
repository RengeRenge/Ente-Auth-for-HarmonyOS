import { huks } from '@kit.UniversalKeystoreKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';

const ALIAS: string = 'ente_auth_local_v1';
const b64: util.Base64Helper = new util.Base64Helper();

function props(purpose: number, iv: Uint8Array | null): Array<huks.HuksParam> {
  const list: Array<huks.HuksParam> = [
    { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_AES },
    { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: purpose },
    { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_PKCS7 },
    { tag: huks.HuksTag.HUKS_TAG_BLOCK_MODE, value: huks.HuksCipherMode.HUKS_MODE_CBC },
  ];
  if (iv !== null) {
    list.push({ tag: huks.HuksTag.HUKS_TAG_IV, value: iv });
  }
  return list;
}

async function ensureKey(): Promise<void> {
  const exists: boolean = await huks.isKeyItemExist(ALIAS, { properties: [] });
  if (exists) return;
  const gen: Array<huks.HuksParam> = [
    { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_AES },
    { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_AES_KEY_SIZE_256 },
    {
      tag: huks.HuksTag.HUKS_TAG_PURPOSE,
      value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT,
    },
    { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_PKCS7 },
    { tag: huks.HuksTag.HUKS_TAG_BLOCK_MODE, value: huks.HuksCipherMode.HUKS_MODE_CBC },
  ];
  await huks.generateKeyItem(ALIAS, { properties: gen });
}

function randomIv(): Uint8Array {
  const r: cryptoFramework.DataBlob = cryptoFramework.createRandom().generateRandomSync(16);
  return r.data;
}

async function encrypt(plain: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const opts: huks.HuksOptions = { properties: props(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT, iv), inData: plain };
  const session: huks.HuksSessionHandle = await huks.initSession(ALIAS, opts);
  const r1: huks.HuksReturnResult = await huks.updateSession(session.handle, opts);
  const r2: huks.HuksReturnResult = await huks.finishSession(session.handle, opts);
  const a: Uint8Array = r1.outData === undefined ? new Uint8Array(0) : r1.outData;
  const b: Uint8Array = r2.outData === undefined ? new Uint8Array(0) : r2.outData;
  const out: Uint8Array = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

async function decrypt(ct: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const opts: huks.HuksOptions = { properties: props(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT, iv), inData: ct };
  const session: huks.HuksSessionHandle = await huks.initSession(ALIAS, opts);
  const r1: huks.HuksReturnResult = await huks.updateSession(session.handle, opts);
  const r2: huks.HuksReturnResult = await huks.finishSession(session.handle, opts);
  const a: Uint8Array = r1.outData === undefined ? new Uint8Array(0) : r1.outData;
  const b: Uint8Array = r2.outData === undefined ? new Uint8Array(0) : r2.outData;
  const out: Uint8Array = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

class Sealed {
  v: number = 1;
  iv: string = '';
  ct: string = '';
}

// 本地持久化封装：优先 HUKS 加密；HUKS 不可用时降级为明文前缀 p:（保证不丢数据）
export class Sealer {
  static async seal(text: string): Promise<string> {
    try {
      await ensureKey();
      const iv: Uint8Array = randomIv();
      const ct: Uint8Array = await encrypt(new util.TextEncoder().encodeInto(text), iv);
      const s: Sealed = new Sealed();
      s.iv = b64.encodeToStringSync(iv);
      s.ct = b64.encodeToStringSync(ct);
      return JSON.stringify(s);
    } catch (e) {
      return 'p:' + text;
    }
  }

  static async unseal(blob: string): Promise<string> {
    if (blob.length === 0) return '';
    if (blob.indexOf('p:') === 0) return blob.substring(2);
    try {
      const s: Sealed = JSON.parse(blob) as Sealed;
      const iv: Uint8Array = b64.decodeSync(s.iv);
      const ct: Uint8Array = b64.decodeSync(s.ct);
      const pt: Uint8Array = await decrypt(ct, iv);
      return new util.TextDecoder().decodeToString(pt);
    } catch (e) {
      return '';
    }
  }
}
