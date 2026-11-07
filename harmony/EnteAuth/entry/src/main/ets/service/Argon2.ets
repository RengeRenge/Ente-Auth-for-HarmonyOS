import { deriveKekNative, argon2SelfTestNative } from 'libentry.so';

// 原生 libentry.so（C++ Argon2id，NAPI 异步线程池执行）派生 KEK：
// Argon2id(password, salt, opsLimit, memLimit, p=1, dkLen=32) → base64(kek)。
// 与官方客户端 KDF 等价（Rust/原生 Argon2id v0x13，libsodium 兼容参数）。
// 失败（如 256MiB 档内存分配失败）时 reject，由调用方回退低档参数重试。
// （ArkVM 解释执行同算法慢约两个数量级，故 KDF 必须走原生库。）
export async function deriveKek(password: string, saltB64: string,
  opsLimit: number, memLimit: number): Promise<string> {
  return await deriveKekNative(password, saltB64, opsLimit, memLimit);
}

// 启动自测：两组已与 noble/libsodium 交叉验证的向量，resolve 'ok' 或 'fail:...'
export async function argon2SelfTest(): Promise<string> {
  return await argon2SelfTestNative();
}
