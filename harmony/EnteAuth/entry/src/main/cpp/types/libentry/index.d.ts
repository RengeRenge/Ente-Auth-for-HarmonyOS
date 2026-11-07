export const deriveKekNative: (password: string, saltB64: string,
  opsLimit: number, memLimit: number) => Promise<string>;
export const argon2SelfTestNative: () => Promise<string>;
