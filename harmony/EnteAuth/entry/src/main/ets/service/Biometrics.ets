import { userAuth } from '@kit.UserAuthenticationKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';

// 生物识别门禁：设备不支持（如模拟器）时直接放行，保证可用性
export class Biometrics {
  static async verify(title: string): Promise<boolean> {
    try {
      const challenge: cryptoFramework.DataBlob = cryptoFramework.createRandom().generateRandomSync(16);
      const authParam: userAuth.AuthParam = {
        challenge: challenge.data,
        authType: [userAuth.UserAuthType.FINGERPRINT, userAuth.UserAuthType.FACE],
        authTrustLevel: userAuth.AuthTrustLevel.ATL2,
      };
      const widgetParam: userAuth.WidgetParam = { title: title };
      const instance: userAuth.UserAuthInstance = userAuth.getUserAuthInstance(authParam, widgetParam);
      return new Promise<boolean>((resolve: (v: boolean) => void) => {
        instance.on('result', {
          onResult: (result: userAuth.UserAuthResult) => {
            const code: number = result.result;
            if (code === userAuth.UserAuthResultCode.SUCCESS) {
              resolve(true);
            } else if (code === userAuth.UserAuthResultCode.CANCELED ||
              code === userAuth.UserAuthResultCode.FAIL ||
              code === userAuth.UserAuthResultCode.TIMEOUT ||
              code === userAuth.UserAuthResultCode.LOCKED) {
              resolve(false);
            } else {
              // 设备不支持 / 未录入 / 系统繁忙：不做门禁，直接放行
              resolve(true);
            }
          },
        });
        instance.start();
      });
    } catch (e) {
      return true;
    }
  }
}
