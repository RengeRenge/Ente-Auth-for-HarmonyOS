import { cryptoFramework } from '@kit.CryptoArchitectureKit';

const B32: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEAM: string = '23456789BCDFGHJKMNPQRTVWXY';

export function base32Decode(input: string): Uint8Array {
  const s: string = input.replace(/\s+/g, '').replace(/-/g, '').toUpperCase();
  let bits: number = 0;
  let value: number = 0;
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const idx: number = B32.indexOf(s.charAt(i));
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

async function digest(alg: string, data: Uint8Array): Promise<Uint8Array> {
  const md: cryptoFramework.Md = cryptoFramework.createMd(alg);
  await md.update({ data: data });
  const out: cryptoFramework.DataBlob = await md.digest();
  return out.data;
}

async function hmacDigest(alg: string, key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const block: number = alg === 'SHA512' ? 128 : 64;
  let k: Uint8Array = key;
  if (k.length > block) k = await digest(alg, k);
  const ipad: Uint8Array = new Uint8Array(block);
  const opad: Uint8Array = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    const kb: number = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  const inner: Uint8Array = new Uint8Array(block + msg.length);
  inner.set(ipad);
  inner.set(msg, block);
  const h1: Uint8Array = await digest(alg, inner);
  const outer: Uint8Array = new Uint8Array(block + h1.length);
  outer.set(opad);
  outer.set(h1, block);
  return digest(alg, outer);
}

function shaName(algorithm: string): string {
  const a: string = algorithm.toLowerCase();
  if (a === 'sha256') return 'SHA256';
  if (a === 'sha512') return 'SHA512';
  return 'SHA1';
}

function padDigits(v: number, digits: number): string {
  let s: string = v.toString();
  while (s.length < digits) s = '0' + s;
  return s;
}

function counterBytes(counter: number): Uint8Array {
  const out: Uint8Array = new Uint8Array(8);
  let c: number = counter;
  for (let i = 7; i >= 0; i--) {
    out[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  return out;
}

function dynamicTruncate(h: Uint8Array): number {
  const off: number = h[h.length - 1] & 0x0f;
  const bin: number = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return bin >>> 0;
}

export class Totp {
  // 返回当前时间步的验证码；type 为 steam 时返回 5 位 Steam Guard 码
  static async generate(
    secret: string,
    algorithm: string,
    digits: number,
    period: number,
    type: string,
    timeOffsetSec: number,
  ): Promise<string> {
    const key: Uint8Array = base32Decode(secret);
    if (key.length === 0) return '';
    const step: number = Math.floor((Date.now() / 1000 + timeOffsetSec) / period);
    return Totp.generateForCounter(key, algorithm, digits, step, type);
  }

  static async generateForCounter(
    key: Uint8Array,
    algorithm: string,
    digits: number,
    step: number,
    type: string,
  ): Promise<string> {
    const h: Uint8Array = await hmacDigest(shaName(algorithm), key, counterBytes(step));
    const bin: number = dynamicTruncate(h);
    if (type === 'steam') {
      let v: number = bin;
      let s: string = '';
      for (let i = 0; i < 5; i++) {
        s += STEAM.charAt(v % STEAM.length);
        v = Math.floor(v / STEAM.length);
      }
      return s;
    }
    const mod: number = Math.pow(10, digits);
    return padDigits(bin % mod, digits);
  }
}
