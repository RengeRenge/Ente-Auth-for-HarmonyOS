import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';

// preferences 的薄封装：同步读写 + 立即落盘
export class Store {
  private pref: preferences.Preferences;

  constructor(ctx: common.Context, name: string) {
    this.pref = preferences.getPreferencesSync(ctx, { name: name });
  }

  get(key: string): string {
    return this.pref.getSync(key, '') as string;
  }

  put(key: string, value: string): void {
    this.pref.putSync(key, value);
    this.pref.flush();
  }

  del(key: string): void {
    this.pref.deleteSync(key);
    this.pref.flush();
  }
}
