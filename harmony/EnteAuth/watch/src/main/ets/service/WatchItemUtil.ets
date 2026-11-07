import { WatchItem, WearRowRaw } from '../model/WatchItem';

// 纯数据转换，不依赖 WearEngine，可被页面静态引用
export function toItem(r: WearRowRaw): WatchItem {
  const it: WatchItem = new WatchItem();
  it.id = r.i;
  it.issuer = r.s;
  it.account = r.a;
  it.secret = r.k;
  it.digits = r.d > 0 ? r.d : 6;
  it.period = r.p > 0 ? r.p : 30;
  it.algorithm = r.g.length > 0 ? r.g : 'sha1';
  it.type = r.t.length > 0 ? r.t : 'totp';
  it.pinned = r.pin === 1;
  return it;
}

export function toRaw(it: WatchItem): WearRowRaw {
  const r: WearRowRaw = {
    i: it.id,
    s: it.issuer,
    a: it.account,
    k: it.secret,
    d: it.digits,
    p: it.period,
    g: it.algorithm,
    t: it.type,
    pin: it.pinned ? 1 : 0,
  };
  return r;
}

// 置顶优先，其余按名称排序
export function sortItems(items: WatchItem[]): void {
  items.sort((a: WatchItem, b: WatchItem): number => {
    if (a.pinned !== b.pinned) {
      return a.pinned ? -1 : 1;
    }
    return a.issuer.localeCompare(b.issuer);
  });
}
