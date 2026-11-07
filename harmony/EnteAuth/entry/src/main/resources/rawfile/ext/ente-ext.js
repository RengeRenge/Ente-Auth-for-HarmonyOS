/**
 * Ente Auth Harmony 注入桥。
 *
 * 说明：本文件是本工程新增的代码，不修改 ente 仓库内任何源码。
 * 它在 auth.ente.com 页面上下文中运行，复用页面已建立的登录态
 * （IndexedDB 中的 token / sessionStorage 中的 master key），
 * 用官方 libsodium 实现与 Rust 侧 wire-compatible 的加解密：
 *   - 密钥盒：crypto_secretbox_easy（XSalsa20-Poly1305）
 *   - 条目：secretstream_xchacha20poly1305 单条 TAG_FINAL（header 24B，ABYTES 17）
 *   - 明文：JSON.stringify(otpauth URI)，codeDisplay 在 URI 查询参数中
 *
 * 通信协议（原生侧驱动）：
 *   __enteExt.cmd('<json>')   入队一条命令 {seq, op, args}
 *   __enteExt.poll()          返回 '{"probe":{...},"results":[{seq,op,ok,payload,error}]}'
 * 采用命令队列而非 JS 直接回调，是因为 runJavaScriptExt 无法接收 Promise 返回值。
 */
(function () {
  "use strict";
  if (window.__enteExt) return;

  var API = "https://api.ente.com";
  // 必须与官方 web 客户端一致：服务端会按该值校验客户端环境
  var PKG = "io.ente.auth.web";
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function b64d(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64e(u8) {
    var s = "";
    var CH = 0x8000;
    for (var i = 0; i < u8.length; i += CH) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
    }
    return btoa(s);
  }

  function sodium() {
    if (!window.sodium) return Promise.reject(new Error("sodium_not_loaded"));
    return Promise.resolve(window.sodium.ready).then(function () {
      return window.sodium;
    });
  }

  // ---------- 存储 ----------

  function readToken() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open("kv", 1);
      req.onsuccess = function () {
        var db = req.result;
        try {
          var g = db.transaction("kv", "readonly").objectStore("kv").get("token");
          g.onsuccess = function () {
            db.close();
            resolve(g.result);
          };
          g.onerror = function () {
            db.close();
            reject(g.error);
          };
        } catch (e) {
          db.close();
          reject(e);
        }
      };
      req.onerror = function () {
        reject(req.error);
      };
    });
  }

  function api(path, opts) {
    return readToken().then(function (token) {
      if (!token) throw new Error("not_logged_in");
      opts = opts || {};
      var headers = { "X-Auth-Token": token, "X-Client-Package": PKG };
      if (opts.body) headers["Content-Type"] = "application/json";
      var init = { method: opts.method || "GET", headers: headers };
      if (opts.body) init.body = opts.body;
      return fetch(API + path, init);
    });
  }

  function jsonOf(res) {
    if (!res.ok) {
      return res.text().then(function (t) {
        throw new Error("http_" + res.status + ":" + t.slice(0, 200));
      });
    }
    return res.json();
  }

  function readMasterKey(s) {
    var raw = sessionStorage.getItem("encryptionKey");
    if (!raw) throw new Error("no_session_master_key");
    var box = JSON.parse(raw);
    var pt = s.crypto_secretbox_open_easy(
      b64d(box.encryptedData),
      b64d(box.nonce),
      b64d(box.key),
    );
    return b64e(pt);
  }

  function readAuthKey(s, masterKey) {
    return api("/authenticator/key").then(function (res) {
      // 404 = 账号尚未创建 authenticator key。与官方移动端
      // getOrCreateAuthDataKey 一致：生成 32 字节随机 key，用 masterKey
      // secretbox 加密后 POST /authenticator/key，供后续 entity 加解密。
      if (res.status === 404) {
        var key = s.randombytes_buf(s.crypto_secretbox_KEYBYTES);
        var nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
        var ct = s.crypto_secretbox_easy(key, nonce, b64d(masterKey));
        return api("/authenticator/key", {
          method: "POST",
          body: JSON.stringify({
            encryptedKey: b64e(ct),
            header: b64e(nonce),
          }),
        }).then(function (res2) {
          if (!res2.ok) throw new Error("http_" + res2.status);
          return b64e(key);
        });
      }
      return jsonOf(res).then(function (j) {
        var pt = s.crypto_secretbox_open_easy(
          b64d(j.encryptedKey),
          b64d(j.header),
          b64d(masterKey),
        );
        return b64e(pt);
      });
    });
  }

  function unhex(h) {
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(h.substr(i * 2, 2), 16);
    }
    return out;
  }

  function hexOf(u8) {
    var out = "";
    for (var i = 0; i < u8.length; i++) {
      out += (u8[i] < 16 ? "0" : "") + u8[i].toString(16);
    }
    return out;
  }

  // 恢复密钥：用主密钥解密 keyAttributes 中的 recoveryKeyEncryptedWithMasterKey，
  // 再按 BIP39（256-bit 熵 + 8-bit 校验）转成 24 个单词，与官方展示一致。
  function mnemonicOf(s, bytes) {
    var words = window.__ENTE_BIP39;
    if (!words || words.length !== 2048) throw new Error("bip39_wordlist_missing");
    return crypto.subtle.digest("SHA-256", bytes).then(function (sig) {
      var hash = new Uint8Array(sig);
      var bits = "";
      for (var i = 0; i < bytes.length; i++) {
        bits += (bytes[i] + 0x100).toString(2).slice(1);
      }
      for (var j = 0; j < 8; j++) {
        bits += (hash[j >> 3] >> (7 - (j % 8))) & 1;
      }
      var out = [];
      for (var k = 0; k < 24; k++) {
        out.push(words[parseInt(bits.substr(k * 11, 11), 2)]);
      }
      return out.join(" ");
    });
  }

  // mnemonicOf 的逆函数：接受 24 词助记词或 64 位十六进制恢复密钥，
  // 返回 32 字节恢复密钥。助记词会校验 BIP39 校验位（SHA-256 前 8 位）。
  // 格式非法 reject invalid_recovery_key，校验位不符 reject incorrect_recovery_key
  function recoveryKeyFromInput(raw) {
    var text = String(raw || "").trim().toLowerCase();
    if (!text) return Promise.reject(new Error("invalid_recovery_key"));
    if (/^[0-9a-f]{64}$/.test(text)) {
      return Promise.resolve(unhex(text));
    }
    var words = window.__ENTE_BIP39;
    if (!words || words.length !== 2048) {
      return Promise.reject(new Error("bip39_wordlist_missing"));
    }
    var parts = text.split(/\s+/);
    if (parts.length !== 24) {
      return Promise.reject(new Error("invalid_recovery_key"));
    }
    var index = {};
    for (var i = 0; i < words.length; i++) index[words[i]] = i;
    var bits = "";
    for (var j = 0; j < 24; j++) {
      if (!Object.prototype.hasOwnProperty.call(index, parts[j])) {
        return Promise.reject(new Error("invalid_recovery_key"));
      }
      bits += (index[parts[j]] + 0x800).toString(2).slice(1);
    }
    var outBytes = new Uint8Array(32);
    for (var k = 0; k < 32; k++) {
      outBytes[k] = parseInt(bits.substr(k * 8, 8), 2);
    }
    return crypto.subtle.digest("SHA-256", outBytes).then(
      function (sig) {
        var hash = new Uint8Array(sig);
        var expect = hash[0];
        var actual = parseInt(bits.substr(256, 8), 2);
        if (expect !== actual) {
          // BIP39 校验位不符 = 助记词有笔误（官方 bip39 解析同样判 malformed）
          throw new Error("invalid_recovery_key");
        }
        return outBytes;
      },
    );
  }

  function encryptEntity(s, plaintext, authKey) {
    var pushed = s.crypto_secretstream_xchacha20poly1305_init_push(
      b64d(authKey),
    );
    var ct = s.crypto_secretstream_xchacha20poly1305_push(
      pushed.state,
      enc.encode(plaintext),
      null,
      s.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    );
    return { encryptedData: b64e(ct), header: b64e(pushed.header) };
  }

  function decryptEntity(s, encryptedData, header, authKey) {
    var state = s.crypto_secretstream_xchacha20poly1305_init_pull(
      b64d(header),
      b64d(authKey),
    );
    var r = s.crypto_secretstream_xchacha20poly1305_pull(
      state,
      b64d(encryptedData),
      null,
    );
    if (!r) throw new Error("decrypt_failed");
    return dec.decode(r.message);
  }

  function withKeys(fn) {
    return sodium().then(function (s) {
      return Promise.resolve()
        .then(function () {
          return readMasterKey(s);
        })
        .then(function (mk) {
          return readAuthKey(s, mk).then(function (ak) {
            return fn(s, ak);
          });
        });
    });
  }

  // ---------- otpauth URI 处理 ----------

  function splitUri(uri) {
    var q = uri.indexOf("?");
    var base = q < 0 ? uri : uri.slice(0, q);
    var params = [];
    if (q >= 0) {
      uri
        .slice(q + 1)
        .split("&")
        .forEach(function (kv) {
          if (!kv) return;
          var i = kv.indexOf("=");
          params.push([
            i < 0 ? kv : kv.slice(0, i),
            i < 0 ? "" : kv.slice(i + 1),
          ]);
        });
    }
    return { base: base, params: params };
  }

  function joinUri(p) {
    if (!p.params.length) return p.base;
    return (
      p.base +
      "?" +
      p.params
        .map(function (x) {
          return x[0] + "=" + x[1];
        })
        .join("&")
    );
  }

  function getParam(p, k) {
    for (var i = 0; i < p.params.length; i++) {
      if (p.params[i][0] === k) return p.params[i][1];
    }
    return null;
  }

  function setParam(p, k, v) {
    for (var i = 0; i < p.params.length; i++) {
      if (p.params[i][0] === k) {
        p.params[i][1] = v;
        return;
      }
    }
    p.params.push([k, v]);
  }

  function safeDecode(v) {
    try {
      return decodeURIComponent(v);
    } catch (e) {
      return v;
    }
  }

  function defaultDisplay() {
    return {
      pinned: false,
      trashed: false,
      lastUsedAt: 0,
      tapCount: 0,
      tags: [],
      note: "",
      position: 0,
      iconSrc: "",
      iconID: "",
    };
  }

  function displayOf(uri) {
    var p = splitUri(uri);
    var raw = getParam(p, "codeDisplay");
    if (!raw) return defaultDisplay();
    try {
      var d = JSON.parse(safeDecode(raw));
      return {
        pinned: !!d.pinned,
        trashed: !!d.trashed,
        lastUsedAt: d.lastUsedAt || 0,
        tapCount: d.tapCount || 0,
        tags: d.tags || [],
        note: d.note || "",
        position: d.position || 0,
        iconSrc: d.iconSrc || "",
        iconID: d.iconID || "",
      };
    } catch (e) {
      return defaultDisplay();
    }
  }

  function withDisplay(uri, mutator) {
    var p = splitUri(uri);
    var d = displayOf(uri);
    mutator(d);
    setParam(p, "codeDisplay", encodeURIComponent(JSON.stringify(d)));
    return joinUri(p);
  }

  // 与 mobile Code.copyWith / fromAccountAndSecret 的 URI 形状保持一致
  function buildUri(o) {
    var type = o.type || "totp";
    var algorithm = (o.algorithm || "SHA1").toUpperCase();
    var digits = o.digits || (type === "steam" ? 5 : 6);
    var period = o.period || 30;
    var issuer = o.issuer || "";
    var account = o.account || "";
    var label = issuer ? issuer + ":" + account : account;
    var path = type + "/" + encodeURIComponent(label).replace(/%3A/g, ":");
    var q =
      "algorithm=" +
      algorithm +
      "&digits=" +
      digits +
      "&issuer=" +
      encodeURIComponent(issuer) +
      "&period=" +
      period +
      "&secret=" +
      encodeURIComponent(o.secret || "");
    if (type === "hotp") q += "&counter=" + (o.counter || 0);
    var uri = "otpauth://" + path + "?" + q;
    var p = splitUri(uri);
    setParam(p, "codeDisplay", encodeURIComponent(JSON.stringify(defaultDisplay())));
    return joinUri(p);
  }

  function parseOtp(uri) {
    var p = splitUri(uri);
    var rest = p.base.replace(/^otpauth:\/\//, "");
    var slash = rest.indexOf("/");
    var type = slash < 0 ? rest : rest.slice(0, slash);
    var label = safeDecode(slash < 0 ? "" : rest.slice(slash + 1));

    var issuer = getParam(p, "issuer");
    issuer = issuer ? safeDecode(issuer) : "";
    if (issuer.indexOf("period=") >= 0) {
      issuer = issuer.slice(0, issuer.indexOf("period="));
    }

    var account = label;
    if (issuer) {
      if (label.indexOf(issuer + ":") === 0) account = label.slice(issuer.length + 1);
    } else if (label.indexOf(":") >= 0) {
      issuer = label.slice(0, label.indexOf(":"));
      account = label.slice(label.indexOf(":") + 1);
    }

    var digits = parseInt(getParam(p, "digits"), 10);
    if (isNaN(digits)) digits = type === "steam" ? 5 : 6;
    var period = parseInt(getParam(p, "period"), 10);
    if (isNaN(period)) period = 30;
    var counter = parseInt(getParam(p, "counter"), 10);
    if (isNaN(counter)) counter = 0;
    var algorithm = (getParam(p, "algorithm") || "SHA1").toLowerCase();
    if (algorithm !== "sha256" && algorithm !== "sha512") algorithm = "sha1";

    var secret = getParam(p, "secret") || "";
    secret = safeDecode(secret).replace(/\s+/g, "").toUpperCase();

    var d = displayOf(uri);
    return {
      type: type,
      issuer: issuer,
      account: account,
      digits: digits,
      period: period,
      counter: counter,
      algorithm: algorithm,
      secret: secret,
      uri: uri,
      pinned: d.pinned,
      trashed: d.trashed,
      note: d.note,
      tags: d.tags,
    };
  }

  // ---------- 原生登录（SRP-4096，与 accounts crate wire-compatible） ----------
  //
  // 官方流程（web/packages/accounts）：
  //   GET  /users/srp/attributes?email=  → {attributes:{srpUserID,srpSalt,kekSalt,
  //                                      opsLimit,memLimit,isEmailMFAEnabled}}（404=未配置）
  //   POST /users/srp/create-session     {srpUserID, srpA}
  //                                     → {sessionID, srpB}
  //   POST /users/srp/verify-session     {srpUserID, sessionID, srpM1}
  //                                     → {id, token|encryptedToken, keyAttributes,
  //                                        srpM2, twoFactorSessionID(V2), passkeySessionID}
  //   POST /users/two-factor/verify      {sessionID, code} → 同上（encryptedToken 形态）
  //
  // 密钥链：kek = argon2id(password, kekSalt, opsLimit, memLimit)；
  // loginKey = crypto_kdf_derive_from_key(32, 1, "loginctx", kek)[..16]；
  // identityHash = SHA256(srpUserID ‖ ":" ‖ loginKey)；
  // x = SHA256(b64d(srpSalt) ‖ identityHash)；
  // k = SHA256(PAD512(N) ‖ PAD512(g))，u = SHA256(PAD512(A) ‖ PAD512(B))；
  // S = (B − k·g^x)^(a + u·x) mod N；
  // M1 = SHA256(PAD512(A)‖PAD512(B)‖PAD512(S))，K = SHA256(PAD512(S))，
  // M2 = SHA256(PAD512(A)‖M1‖K)（与 Go 服务端 golden vector 一致）。

  var SRP_N_HEX =
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020" +
    "bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe135" +
    "6d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5" +
    "a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55" +
    "d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966" +
    "d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b" +
    "2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d22" +
    "61898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb8504" +
    "58dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a2" +
    "5619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b20" +
    "0cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4" +
    "b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a94" +
    "6834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c594" +
    "74e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd7621" +
    "70481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063" +
    "199ffffffffffffffff";

  var SRP_N = null; // BigInt，惰性初始化（旧内核若不支持 BigInt 则仅登录不可用）
  var SRP_K_PROMISE = null;

  function srpInit() {
    if (typeof BigInt !== "function") {
      return Promise.reject(new Error("bigint_unsupported"));
    }
    if (!SRP_K_PROMISE) {
      SRP_N = bytesToBig(unhex(SRP_N_HEX));
      var nPadded = pad512(unhex(SRP_N_HEX));
      var gPadded = pad512(bigToBytes(5n));
      SRP_K_PROMISE = sha256Cat(nPadded, gPadded).then(bytesToBig);
    }
    return SRP_K_PROMISE;
  }

  function bytesToBig(u8) {
    var x = 0n;
    for (var i = 0; i < u8.length; i++) x = (x << 8n) | BigInt(u8[i]);
    return x;
  }

  function bigToBytes(x) {
    if (x === 0n) return new Uint8Array([0]);
    var n = 0;
    var t = x;
    while (t > 0n) {
      n++;
      t >>= 8n;
    }
    var out = new Uint8Array(n);
    for (var i = n - 1; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function pad512(u8) {
    if (u8.length >= 512) return u8;
    var out = new Uint8Array(512);
    out.set(u8, 512 - u8.length);
    return out;
  }

  function modpow(base, exp, mod) {
    var result = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  }

  // libsodium 不提供 SHA-256，用 Web Crypto 拼接多段再摘要
  function sha256Cat() {
    var total = 0;
    for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
    var buf = new Uint8Array(total);
    var off = 0;
    for (var j = 0; j < arguments.length; j++) {
      buf.set(arguments[j], off);
      off += arguments[j].length;
    }
    return crypto.subtle.digest("SHA-256", buf).then(function (d) {
      return new Uint8Array(d);
    });
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  // 官方 decode_plain_token：先 url-safe 再标准 b64
  function b64dFlexible(s) {
    try {
      return b64d(s);
    } catch (e) {}
    return b64d(String(s).replace(/-/g, "+").replace(/_/g, "/"));
  }

  // 完整 SRP-4096 客户端计算。返回 {aPubPadded, m1, m2}
  function srpCompute(aPrivBig, identity, salt, loginKey, serverB) {
    return srpInit().then(function (k) {
      var aPubBig = modpow(5n, aPrivBig, SRP_N);
      var aPubBytes = bigToBytes(aPubBig);
      var bBig = bytesToBig(serverB);
      if (bBig % SRP_N === 0n) throw new Error("bad_server_b");
      return sha256Cat(pad512(aPubBytes), pad512(serverB))
        .then(function (uH) {
          var u = bytesToBig(uH);
          return sha256Cat(identity, new Uint8Array([0x3a]), loginKey).then(
            function (idH) {
              return sha256Cat(salt, idH).then(function (xH) {
                var x = bytesToBig(xH);
                var gx = modpow(5n, x, SRP_N);
                var base = ((bBig - k * gx) % SRP_N + SRP_N) % SRP_N;
                var sBig = modpow(base, aPrivBig + u * x, SRP_N);
                var sBytes = bigToBytes(sBig);
                return sha256Cat(
                  pad512(aPubBytes),
                  pad512(serverB),
                  pad512(sBytes),
                ).then(function (m1) {
                  return sha256Cat(pad512(sBytes)).then(function (kSess) {
                    return sha256Cat(pad512(aPubBytes), m1, kSess).then(
                      function (m2) {
                        return { aPubPadded: pad512(aPubBytes), m1: m1, m2: m2 };
                      },
                    );
                  });
                });
              });
            },
          );
        });
    });
  }

  // 无 token 的登录期 API 调用（opts.token 可选：注册期 signup token）
  function apiAnon(path, opts) {
    opts = opts || {};
    var headers = { "X-Client-Package": PKG };
    if (opts.token) headers["X-Auth-Token"] = opts.token;
    if (opts.body) headers["Content-Type"] = "application/json";
    var init = { method: opts.method || "GET", headers: headers };
    if (opts.body) init.body = opts.body;
    var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    if (ctrl) {
      init.signal = ctrl.signal;
      setTimeout(function () {
        ctrl.abort();
      }, 30000);
    }
    return fetch(API + path, init);
  }

  // 解析服务端错误体 {"code": "...", "message": "..."}（core/http.rs ApiErrorEnvelope）
  function apiErrorCode(res) {
    return res
      .text()
      .then(function (t) {
        try {
          var j = JSON.parse(t);
          if (j && typeof j.code === "string") return j.code;
        } catch (e) {}
        return "";
      })
      .catch(function () {
        return "";
      });
  }

  function uuidV4() {
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var h = hexOf(b);
    return (
      h.substr(0, 8) +
      "-" +
      h.substr(8, 4) +
      "-" +
      h.substr(12, 4) +
      "-" +
      h.substr(16, 4) +
      "-" +
      h.substr(20, 12)
    );
  }

  // 注册期 SRP verifier（对应 srp crate compute_verifier：
  // x = SHA256(srpSalt ‖ SHA256(srpUserID ‖ ":" ‖ loginKey))，v = 5^x mod N，
  // 最短大端字节 to_be_bytes_trimmed_vartime，不补 512）
  function srpVerifierOf(identity, salt, loginKey) {
    return srpInit().then(function () {
      return sha256Cat(identity, new Uint8Array([0x3a]), loginKey).then(
        function (idH) {
          return sha256Cat(salt, idH).then(function (xH) {
            var x = bytesToBig(xH);
            var v = modpow(5n, x, SRP_N);
            return bigToBytes(v);
          });
        },
      );
    });
  }

  function idbPutToken(token) {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open("kv", 1);
      req.onupgradeneeded = function () {
        try {
          req.result.createObjectStore("kv");
        } catch (e) {}
      };
      req.onsuccess = function () {
        var db = req.result;
        try {
          var tx = db.transaction("kv", "readwrite");
          tx.objectStore("kv").put(token, "token");
          tx.oncomplete = function () {
            db.close();
            resolve(true);
          };
          tx.onerror = function () {
            db.close();
            reject(tx.error || new Error("idb_put_failed"));
          };
          tx.onabort = function () {
            db.close();
            reject(tx.error || new Error("idb_aborted"));
          };
        } catch (e) {
          db.close();
          reject(e);
        }
      };
      req.onerror = function () {
        reject(req.error);
      };
    });
  }

  // 跨命令的登录上下文（仅内存；页面刷新即失效，需重新输密码）
  var loginCtx = null; // {email, srpAttrs, kek, pending2fa, ottPurpose, otpAuth, passkey, signupKeys, usedTwoFactor}

  function twoFactorSessionIdOf(auth) {
    var v1 = auth.twoFactorSessionID;
    var v2 = auth.twoFactorSessionIDV2;
    var id = typeof v1 === "string" && v1 ? v1 : typeof v2 === "string" && v2 ? v2 : "";
    return id;
  }

  // 登录收尾（已知 masterKey 的调用方直接使用）：解密 token，
  // 写回与官方 web 完全一致的本地状态：
  //   IndexedDB kv.token = 明文 JWT
  //   localStorage.user / keyAttributes / srpAttributes
  //   sessionStorage.encryptionKey = {encryptedData, key, nonce}（masterKey 盒）
  function finishLoginWithMasterKey(s, ctx, auth, masterKey, isTwoFactor) {
    var kA = auth.keyAttributes;
    if (!kA) throw new Error("no_key_attributes");
    var token;
    if (auth.encryptedToken) {
      // encryptedToken 是用账户公钥封装的 sealed box，需 masterKey 解出 secretKey
      // （SRP 无 2FA 与 2FA 两条路径均返回 encryptedToken，见 server userauth.go）
      var secretKey = s.crypto_secretbox_open_easy(
        b64d(kA.encryptedSecretKey),
        b64d(kA.secretKeyDecryptionNonce),
        masterKey,
      );
      var rawToken = s.crypto_box_seal_open(
        b64d(auth.encryptedToken),
        b64d(kA.publicKey),
        secretKey,
      );
      // 服务端封箱前先做 base64url 解码（crypto.go GetEncryptedToken），
      // 开箱得到的是原始二进制；须按官方客户端 encode_url_safe（URL-safe 带
      // padding）重新编码才是可用的 token 字符串，直接按 UTF-8 解码会得到
      // 含 U+FFFD 的乱码，导致 X-Auth-Token 请求头非法。
      token = b64e(rawToken).replace(/\+/g, "-").replace(/\//g, "_");
    } else {
      // 明文 token 字段本身就是 base64url 字符串，原样使用
      // （官方客户端解码后再 encode_url_safe 会还原为同一字符串）
      token = String(auth.token);
    }
    if (!token) throw new Error("no_token");

    var user = { id: auth.id, email: ctx.email, token: token };
    if (isTwoFactor) user.isTwoFactorEnabled = true;

    // masterKey 会话盒（与 saveMasterKeyInSessionAndSafeStore 一致）
    var sessionKeyBytes = s.randombytes_buf(32);
    var nonceB = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
    var cipher = s.crypto_secretbox_easy(masterKey, nonceB, sessionKeyBytes);

    return idbPutToken(token).then(function () {
      try {
        localStorage.setItem("user", JSON.stringify(user));
        localStorage.setItem("keyAttributes", JSON.stringify(kA));
        if (ctx.srpAttrs) {
          localStorage.setItem("srpAttributes", JSON.stringify(ctx.srpAttrs));
        }
        localStorage.removeItem("__enteSignedOut");
        sessionStorage.setItem(
          "encryptionKey",
          JSON.stringify({
            encryptedData: b64e(cipher),
            key: b64e(sessionKeyBytes),
            nonce: b64e(nonceB),
          }),
        );
      } catch (e) {
        throw new Error("persist_failed");
      }
      loginCtx = null;
      return { done: true };
    });
  }

  // 登录收尾（密码路径）：用 ctx.kek 解密 masterKey 后走统一收尾
  function finishLoginInternal(s, ctx, auth, isTwoFactor) {
    var kA = auth.keyAttributes;
    if (!kA) throw new Error("no_key_attributes");
    var masterKey;
    try {
      masterKey = s.crypto_secretbox_open_easy(
        b64d(kA.encryptedKey),
        b64d(kA.keyDecryptionNonce),
        ctx.kek,
      );
    } catch (e) {
      throw new Error("decrypt_master_key_failed");
    }
    return finishLoginWithMasterKey(s, ctx, auth, masterKey, isTwoFactor);
  }

  // 登录响应分流（对应 rust LoginFlow::advance + Signup::verified）：
  //   passkey → twofactor →（有 kek）直接完成 /（无 kek）输密码解锁 → 无 keyAttributes 设密码
  function classifyAuthResponse(s, ctx, auth, isTwoFactor) {
    if (auth.passkeySessionID) {
      var tf = twoFactorSessionIdOf(auth);
      if (tf) ctx.pending2fa = { sessionID: tf };
      ctx.passkey = {
        sessionID: String(auth.passkeySessionID),
        accountsUrl: auth.accountsUrl
          ? String(auth.accountsUrl)
          : "https://accounts.ente.com",
        totp2FASessionID: tf,
      };
      return Promise.resolve({ next: "passkey" });
    }
    var sid = twoFactorSessionIdOf(auth);
    if (sid) {
      ctx.pending2fa = { sessionID: sid };
      return Promise.resolve({ next: "twofactor" });
    }
    var kA = auth.keyAttributes;
    var hasToken = !!auth.token || !!auth.encryptedToken;
    if (kA && hasToken) {
      if (ctx.kek) {
        return finishLoginInternal(s, ctx, auth, isTwoFactor).then(function () {
          return { next: "done" };
        });
      }
      ctx.otpAuth = auth;
      // 随分流下发 kdf 参数：原生层据此派生 kek 后调 unlockWithPassword
      return Promise.resolve({
        next: "unlock",
        kekSalt: kA.kekSalt,
        opsLimit: kA.opsLimit,
        memLimit: kA.memLimit,
      });
    }
    if (!kA && hasToken) {
      ctx.otpAuth = auth;
      return Promise.resolve({ next: "setpassword" });
    }
    return Promise.reject(new Error("bad_auth_response"));
  }

  // ---------- 数据访问 ----------

  function fetchAll(s, ak) {
    var sinceTime = 0;
    var byId = {};
    function pump() {
      return api(
        "/authenticator/entity/diff?sinceTime=" + sinceTime + "&limit=1000",
      )
        .then(jsonOf)
        .then(function (j) {
          var diff = j.diff || [];
          for (var i = 0; i < diff.length; i++) {
            var c = diff[i];
            if (c.updatedAt > sinceTime) sinceTime = c.updatedAt;
            if (c.isDeleted) {
              delete byId[c.id];
            } else {
              byId[c.id] = {
                id: c.id,
                updatedAt: c.updatedAt,
                encryptedData: c.encryptedData,
                header: c.header,
              };
            }
          }
          if (diff.length) return pump();
          var out = [];
          for (var id in byId) {
            var e = byId[id];
            var plain = null;
            try {
              plain = decryptEntity(s, e.encryptedData, e.header, ak);
            } catch (err) {
              plain = null;
            }
            out.push({ id: e.id, updatedAt: e.updatedAt, plain: plain });
          }
          return out;
        });
    }
    return pump();
  }

  function toRows(items) {
    var rows = [];
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (!it.plain) {
        rows.push({
          id: it.id,
          updatedAt: it.updatedAt,
          broken: true,
          uri: "",
          issuer: "",
          account: "",
          digits: 6,
          period: 30,
          algorithm: "sha1",
          type: "totp",
          secret: "",
          counter: 0,
          pinned: false,
          trashed: false,
          note: "",
          tags: [],
        });
        continue;
      }
      var row;
      try {
        row = parseOtp(JSON.parse(it.plain));
      } catch (e) {
        row = parseOtp(it.plain);
      }
      row.id = it.id;
      row.updatedAt = it.updatedAt;
      row.broken = false;
      rows.push(row);
    }
    rows.sort(function (a, b) {
      return (b.updatedAt || 0) - (a.updatedAt || 0);
    });
    return rows;
  }

  var cache = {};

  function putEntity(s, ak, id, uri) {
    var blob = encryptEntity(s, JSON.stringify(uri), ak);
    var body = JSON.stringify({
      id: id,
      encryptedData: blob.encryptedData,
      header: blob.header,
    });
    return api("/authenticator/entity", { method: "PUT", body: body }).then(
      function (res) {
        if (!res.ok) throw new Error("http_" + res.status);
        return id;
      },
    );
  }

  function mutateDisplay(id, mutator) {
    return withKeys(function (s, ak) {
      var row = cache[id];
      if (!row) throw new Error("not_in_cache");
      var uri = withDisplay(row.uri, mutator);
      return putEntity(s, ak, id, uri).then(function () {
        row.uri = uri;
        var d = displayOf(uri);
        row.pinned = d.pinned;
        row.trashed = d.trashed;
        row.note = d.note;
        row.tags = d.tags;
        return parseOtp(uri);
      });
    });
  }

  // ---------- 命令实现 ----------

  var OPS = {
    list: function () {
      return withKeys(function (s, ak) {
        return fetchAll(s, ak).then(function (items) {
          var rows = toRows(items);
          cache = {};
          for (var i = 0; i < rows.length; i++) cache[rows[i].id] = rows[i];
          return rows;
        });
      });
    },

    add: function (a) {
      return withKeys(function (s, ak) {
        var uri = buildUri(a);
        var blob = encryptEntity(s, JSON.stringify(uri), ak);
        return api("/authenticator/entity", {
          method: "POST",
          body: JSON.stringify(blob),
        })
          .then(jsonOf)
          .then(function (j) {
            var row = parseOtp(uri);
            row.id = j.id;
            row.updatedAt = Date.now() * 1000;
            cache[j.id] = row;
            return row;
          });
      });
    },

    update: function (a) {
      return withKeys(function (s, ak) {
        var old = cache[a.id];
        if (!old) throw new Error("not_in_cache");
        var cur = displayOf(old.uri);
        // 以新构造的 URI 为基底，仅保留原条目的 display（置顶/回收站/备注/标签/图标）
        var uri = withDisplay(buildUri(a), function (d) {
          d.pinned = cur.pinned;
          d.trashed = cur.trashed;
          d.lastUsedAt = cur.lastUsedAt;
          d.tapCount = cur.tapCount;
          d.tags = cur.tags;
          d.note = cur.note;
          d.position = cur.position;
          d.iconSrc = cur.iconSrc;
          d.iconID = cur.iconID;
        });
        return putEntity(s, ak, a.id, uri).then(function () {
          var row = parseOtp(uri);
          row.id = a.id;
          row.updatedAt = Date.now() * 1000;
          cache[a.id] = row;
          return row;
        });
      });
    },

    setPinned: function (a) {
      return mutateDisplay(a.id, function (d) {
        d.pinned = !!a.pinned;
      });
    },

    setTrashed: function (a) {
      return mutateDisplay(a.id, function (d) {
        d.trashed = !!a.trashed;
      });
    },

    setNote: function (a) {
      return mutateDisplay(a.id, function (d) {
        d.note = a.note || "";
      });
    },

    setTags: function (a) {
      return mutateDisplay(a.id, function (d) {
        d.tags = Array.isArray(a.tags) ? a.tags.filter(function (t) { return typeof t === "string" && t.length > 0; }) : [];
      });
    },

    remove: function (a) {
      return api("/authenticator/entity?id=" + encodeURIComponent(a.id), {
        method: "DELETE",
      }).then(function (res) {
        if (!res.ok) throw new Error("http_" + res.status);
        delete cache[a.id];
        return a.id;
      });
    },

    // 导入：接收 [{issuer, account, secret, digits, period, algorithm}]
    importMany: function (a) {
      var list = a.items || [];
      var done = [];
      var failed = [];
      function step(i) {
        if (i >= list.length) return { done: done, failed: failed };
        return OPS.add(list[i])
          .then(function () {
            done.push(i);
            return step(i + 1);
          })
          .catch(function (e) {
            failed.push({ index: i, error: e.message });
            return step(i + 1);
          });
      }
      return step(0);
    },

    // ---- 账户 / 安全（复用网页已登录 token 直接调用 Ente API） ----

    getUser: function () {
      var u = null;
      try {
        u = JSON.parse(localStorage.getItem("user") || "null");
      } catch (e) {
        u = null;
      }
      return {
        email: u && u.email ? u.email : "",
        isTwoFactorEnabled: u ? !!u.isTwoFactorEnabled : false,
      };
    },

    recoveryKey: function () {
      return sodium().then(function (s) {
        var mk = readMasterKey(s);
        var attrs = JSON.parse(localStorage.getItem("keyAttributes") || "null");
        if (!attrs || !attrs.recoveryKeyEncryptedWithMasterKey) {
          throw new Error("no_recovery_key");
        }
        var bytes = s.crypto_secretbox_open_easy(
          b64d(attrs.recoveryKeyEncryptedWithMasterKey),
          b64d(attrs.recoveryKeyDecryptionNonce),
          b64d(mk),
        );
        return mnemonicOf(s, bytes).then(function (mnemonic) {
          return { mnemonic: mnemonic, hex: hexOf(bytes) };
        });
      });
    },

    sessions: function () {
      return Promise.all([api("/users/sessions").then(jsonOf), readToken()]).then(
        function (r) {
          var list = r[0].sessions || [];
          var current = r[1] || "";
          return {
            sessions: list.map(function (s) {
              s.isCurrent = s.isCurrent === true ||
                (current.length > 0 && s.token === current);
              return s;
            }),
          };
        },
      );
    },

    terminateSession: function (a) {
      return api("/users/session?token=" + encodeURIComponent(a.token), {
        method: "DELETE",
      }).then(function (res) {
        if (!res.ok) throw new Error("http_" + res.status);
        return true;
      });
    },

    // 发送修改邮箱的验证码（与官方 sendOTT(email, "change") 一致）
    sendChangeEmailOtt: function (a) {
      return api("/users/ott", {
        method: "POST",
        body: JSON.stringify({ email: a.email, purpose: "change" }),
      }).then(function (res) {
        if (!res.ok) throw new Error("http_" + res.status);
        return true;
      });
    },

    changeEmail: function (a) {
      return api("/users/change-email", {
        method: "POST",
        body: JSON.stringify({ email: a.email, ott: a.ott }),
      }).then(function (res) {
        if (!res.ok) throw new Error("http_" + res.status);
        var u = JSON.parse(localStorage.getItem("user") || "{}");
        u.email = a.email;
        localStorage.setItem("user", JSON.stringify(u));
        return { email: a.email };
      });
    },

    // 修改密码（对应 rust change_password）：当前会话已认证，仅需新密码。
    // ArkTS 侧已用原生 Argon2id（Sensitive 阶梯 256MiB/16 → 128MiB/32）+
    // 新随机 kekSalt 派生 kekB64；masterKey 不变，只更新 KEK 与 SRP 凭据：
    // secretbox(masterKey, 新KEK) → srpVerifierOf(新 srpUserID/srpSalt/loginKey)
    // → POST /users/srp/setup → POST /users/srp/update（updatedKeyAttr 仅 5 字段）
    // → 校验 srpM2 → 同步本地 keyAttributes / srpAttributes。
    changePassword: function (a) {
      var kek = b64d(String(a.kekB64 || ""));
      if (kek.length !== 32) throw new Error("bad_kek");
      var kekSaltB64 = String(a.kekSaltB64 || "");
      var opsLimit = Number(a.opsLimit);
      var memLimit = Number(a.memLimit);
      if (
        !kekSaltB64 ||
        b64d(kekSaltB64).length !== 16 ||
        !isFinite(opsLimit) ||
        !isFinite(memLimit) ||
        opsLimit < 1 ||
        memLimit < 134217728
      ) {
        throw new Error("bad_kdf_params");
      }
      return sodium().then(function (s) {
        var masterKey = b64d(readMasterKey(s));
        var kA = JSON.parse(localStorage.getItem("keyAttributes") || "null");
        if (!kA || !kA.encryptedKey) throw new Error("no_key_attributes");
        var loginKey = s.crypto_kdf_derive_from_key(32, 1, "loginctx", kek)
          .subarray(0, 16);
        var kdfNonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
        var encryptedKey = s.crypto_secretbox_easy(masterKey, kdfNonce, kek);
        var srpUserID = uuidV4();
        var srpSalt = s.randombytes_buf(16);
        var aPrivBig = bytesToBig(s.randombytes_buf(64));
        var aPubBig = modpow(5n, aPrivBig, SRP_N);
        var srpA = b64e(pad512(bigToBytes(aPubBig)));
        var srpSaltB64 = b64e(srpSalt);
        var updatedKeyAttr = {
          kekSalt: kekSaltB64,
          encryptedKey: b64e(encryptedKey),
          keyDecryptionNonce: b64e(kdfNonce),
          opsLimit: opsLimit,
          memLimit: memLimit,
        };
        return srpVerifierOf(enc.encode(srpUserID), srpSalt, loginKey).then(
          function (verifier) {
            return api("/users/srp/setup", {
              method: "POST",
              body: JSON.stringify({
                srpUserID: srpUserID,
                srpSalt: srpSaltB64,
                srpVerifier: b64e(verifier),
                srpA: srpA,
              }),
            })
              .then(jsonOf)
              .then(function (setup) {
                if (!setup || !setup.setupID || !setup.srpB) {
                  throw new Error("bad_setup");
                }
                return srpCompute(
                  aPrivBig,
                  enc.encode(srpUserID),
                  srpSalt,
                  loginKey,
                  b64d(setup.srpB),
                ).then(function (r) {
                  return api("/users/srp/update", {
                    method: "POST",
                    body: JSON.stringify({
                      setupID: String(setup.setupID),
                      srpM1: b64e(r.m1),
                      updatedKeyAttr: updatedKeyAttr,
                      logOutOtherDevices: a.logOutOtherDevices === true,
                    }),
                  })
                    .then(jsonOf)
                    .then(function (resp) {
                      if (
                        !resp ||
                        !resp.srpM2 ||
                        !bytesEqual(b64dFlexible(resp.srpM2), r.m2)
                      ) {
                        throw new Error("m2_mismatch");
                      }
                      // 与官方 put_key_attributes / put_srp_attributes 一致，
                      // 更新本地副本供本设备后续解锁 / 登录使用
                      kA.kekSalt = kekSaltB64;
                      kA.encryptedKey = updatedKeyAttr.encryptedKey;
                      kA.keyDecryptionNonce = updatedKeyAttr.keyDecryptionNonce;
                      kA.opsLimit = opsLimit;
                      kA.memLimit = memLimit;
                      localStorage.setItem(
                        "keyAttributes",
                        JSON.stringify(kA),
                      );
                      localStorage.setItem(
                        "srpAttributes",
                        JSON.stringify({
                          kekSalt: kekSaltB64,
                          memLimit: memLimit,
                          opsLimit: opsLimit,
                          srpSalt: srpSaltB64,
                          srpUserID: srpUserID,
                        }),
                      );
                      return { done: true };
                    });
                });
              });
          },
        );
      });
    },

    // 恢复账户（对应官方 recover_account）：OTP 登录后忘记密码时，
    // 用 24 词助记词或 64 位十六进制恢复密钥解密
    // keyAttributes.masterKeyEncryptedWithRecoveryKey 得到 masterKey 完成登录，
    // 之后由原生层引导设置新密码（changePassword）
    recoverAccount: function (a) {
      if (!loginCtx || !loginCtx.otpAuth || !loginCtx.otpAuth.keyAttributes) {
        throw new Error("no_login_ctx");
      }
      var ctx = loginCtx;
      var auth = ctx.otpAuth;
      var kA = auth.keyAttributes;
      if (
        !kA.masterKeyEncryptedWithRecoveryKey ||
        !kA.masterKeyDecryptionNonce
      ) {
        throw new Error("no_recovery_key");
      }
      return recoveryKeyFromInput(a.recoveryKey).then(function (rkBytes) {
        return sodium().then(function (s) {
          var masterKey;
          try {
            masterKey = s.crypto_secretbox_open_easy(
              b64d(kA.masterKeyEncryptedWithRecoveryKey),
              b64d(kA.masterKeyDecryptionNonce),
              rkBytes,
            );
          } catch (e) {
            throw new Error("incorrect_recovery_key");
          }
          return finishLoginWithMasterKey(
            s,
            ctx,
            auth,
            masterKey,
            ctx.usedTwoFactor === true,
          );
        });
      });
    },

    // 电子邮件验证（官方 email MFA）：读取状态 / 开关
    emailMfaStatus: function () {
      return api("/users/details/v2?memoryCount=false").then(jsonOf).then(function (j) {
        var p = j.profileData || {};
        return {
          enabled: p.isEmailMFAEnabled === true,
          canDisable: p.canDisableEmailMFA !== false,
        };
      });
    },

    setEmailMfa: function (a) {
      return api("/users/email-mfa", {
        method: "PUT",
        body: JSON.stringify({ isEnabled: a.enabled === true }),
      }).then(function (res) {
        if (!res.ok) throw new Error("http_" + res.status);
        return { enabled: a.enabled === true };
      });
    },

    // 通行密钥管理：与官方一致，先确保已配置恢复密钥，再取 accounts token 拼出管理页地址
    passkeyUrl: function () {
      function ensureRecovery() {
        return OPS.recoveryKey()
          .then(function (rk) {
            return sodium().then(function (s) {
              return api("/users/two-factor/recovery-status")
                .then(jsonOf)
                .then(function (st) {
                  if (st && st.isPasskeyRecoveryEnabled) return true;
                  var secret = s.randombytes_buf(32);
                  var nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
                  var cipher = s.crypto_secretbox_easy(secret, nonce, unhex(rk.hex));
                  return api("/users/two-factor/passkeys/configure-recovery", {
                    method: "POST",
                    body: JSON.stringify({
                      secret: b64e(secret),
                      userSecretCipher: b64e(cipher),
                      userSecretNonce: b64e(nonce),
                    }),
                  }).then(function (res) {
                    // 已配置等情况不阻塞管理页打开
                    return res.ok || res.status === 409;
                  });
                });
            });
          })
          .catch(function () {
            return false;
          });
      }
      return ensureRecovery()
        .then(function () {
          return api("/users/accounts-token").then(jsonOf);
        })
        .then(function (t) {
          var base = String(t.accountsUrl || "https://accounts.ente.com")
            .replace(/\/+$/, "");
          return { url: base + "/passkeys?token=" + encodeURIComponent(t.accountsToken) };
        });
    },

    // 删除账户（官方 deletion.rs delete_account）：
    //   1) GET /users/delete-challenge → encryptedChallenge 是用账户公钥
    //      crypto_box_seal 密封的 "delete-jwt<jwt>"
    //   2) 用 secretbox(masterKey) 解出的 secretKey 与公钥开封，去掉
    //      "delete-jwt" 前缀得到 challenge（JWT）
    //   3) DELETE /users/delete {challenge, reasonCategory}
    deleteAccount: function () {
      return sodium().then(function (s) {
        var kA = JSON.parse(localStorage.getItem("keyAttributes") || "null");
        if (
          !kA ||
          !kA.publicKey ||
          !kA.encryptedSecretKey ||
          !kA.secretKeyDecryptionNonce
        ) {
          throw new Error("no_key_attributes");
        }
        var secretKey = s.crypto_secretbox_open_easy(
          b64d(kA.encryptedSecretKey),
          b64d(kA.secretKeyDecryptionNonce),
          b64d(readMasterKey(s)),
        );
        return api("/users/delete-challenge")
          .then(jsonOf)
          .then(function (j) {
            var plaintext = dec.decode(
              s.crypto_box_seal_open(
                b64d(j.encryptedChallenge),
                b64d(kA.publicKey),
                secretKey,
              ),
            );
            if (plaintext.indexOf("delete-jwt") !== 0) {
              throw new Error("bad_challenge");
            }
            return plaintext.slice("delete-jwt".length);
          })
          .then(function (challenge) {
            return api("/users/delete", {
              method: "DELETE",
              body: JSON.stringify({
                challenge: challenge,
                reasonCategory: "not_listed",
              }),
            });
          })
          .then(function (res) {
            if (!res.ok) throw new Error("http_" + res.status);
            return true;
          });
      });
    },

    // ---- 原生分步登录 ----

    // 第一步：查询 SRP 属性。404 表示该邮箱未配置密码登录
    // （未注册 / 仅 email OTP / 老账户），原生侧引导走网页登录。
    loginPrepare: function (a) {
      var email = String(a.email || "").trim();
      if (!email) throw new Error("bad_email");
      return apiAnon(
        "/users/srp/attributes?email=" + encodeURIComponent(email),
      ).then(function (res) {
        if (res.status === 404) throw new Error("no_srp");
        if (!res.ok) throw new Error("http_" + res.status);
        return res.json().then(function (j) {
          var at = j && j.attributes ? j.attributes : null;
          if (
            !at ||
            !at.srpUserID ||
            typeof at.srpSalt !== "string" ||
            typeof at.kekSalt !== "string" ||
            typeof at.opsLimit !== "number" ||
            typeof at.memLimit !== "number"
          ) {
            throw new Error("bad_attributes");
          }
          loginCtx = {
            email: email,
            srpAttrs: at,
            kek: null,
            pending2fa: null,
            ottPurpose: null,
            otpAuth: null,
            passkey: null,
            signupKeys: null,
            usedTwoFactor: false,
          };
          // KDF 参数随响应下发：原生层 taskpool Argon2id 派生 kek 后再调 loginPassword
          return {
            isEmailMFAEnabled: at.isEmailMFAEnabled === true,
            kekSalt: at.kekSalt,
            opsLimit: at.opsLimit,
            memLimit: at.memLimit,
          };
        });
      });
    },

    // 第二步：SRP-4096 → 拿 token（或转入 2FA）。
    // kek 由原生层（taskpool Argon2id，loginPrepare 下发的参数）派生后以 kekB64 传入，
    // wasm 内不再跑大参数 crypto_pwhash（webview 内存受限会挂死/被杀）。
    loginPassword: function (a) {
      if (!loginCtx) throw new Error("no_login_ctx");
      var ctx = loginCtx;
      var at = ctx.srpAttrs;
      return srpInit()
        .then(function () {
          return sodium();
        })
        .then(function (s) {
          // 1. kek = 原生 argon2id(password, kekSalt, opsLimit, memLimit)
          var kek = b64d(String(a.kekB64 || ""));
          if (kek.length !== 32) throw new Error("bad_kek");
          ctx.kek = kek;
          // 2. loginKey = kdf_subkey(kek)[..16]
          var loginKey = s.crypto_kdf_derive_from_key(
            32,
            1,
            "loginctx",
            kek,
          ).subarray(0, 16);
          // 3. SRP 会话
          var aPrivBig = bytesToBig(s.randombytes_buf(64));
          var identity = enc.encode(String(at.srpUserID));
          var saltBytes = b64d(at.srpSalt);
          var aPubBig = modpow(5n, aPrivBig, SRP_N);
          var srpA = b64e(pad512(bigToBytes(aPubBig)));
          return apiAnon("/users/srp/create-session", {
            method: "POST",
            body: JSON.stringify({
              srpUserID: String(at.srpUserID),
              srpA: srpA,
            }),
          })
            .then(jsonOf)
            .then(function (session) {
              if (!session || !session.srpB || !session.sessionID) {
                throw new Error("bad_session");
              }
              var serverB = b64d(session.srpB);
              return srpCompute(aPrivBig, identity, saltBytes, loginKey, serverB)
                .then(function (r) {
                  return apiAnon("/users/srp/verify-session", {
                    method: "POST",
                    body: JSON.stringify({
                      srpUserID: String(at.srpUserID),
                      sessionID: String(session.sessionID),
                      srpM1: b64e(r.m1),
                    }),
                  }).then(function (res) {
                    if (res.status === 410) throw new Error("session_expired");
                    if (res.status === 401) throw new Error("incorrect_password");
                    if (!res.ok) throw new Error("http_" + res.status);
                    return res.json().then(function (auth) {
                      // 校验服务端 M2
                      if (
                        !auth.srpM2 ||
                        !bytesEqual(b64dFlexible(auth.srpM2), r.m2)
                      ) {
                        throw new Error("m2_mismatch");
                      }
                      if (auth.passkeySessionID) {
                        // passkey 二次验证：记录会话（accountsUrl 为服务端随响应下发），
                        // 同时保留 twoFactorSessionID 供「使用 TOTP 登录」切换
                        var tfSid = twoFactorSessionIdOf(auth);
                        if (tfSid) ctx.pending2fa = { sessionID: tfSid };
                        ctx.passkey = {
                          sessionID: String(auth.passkeySessionID),
                          accountsUrl: auth.accountsUrl
                            ? String(auth.accountsUrl)
                            : "https://accounts.ente.com",
                          totp2FASessionID: tfSid,
                        };
                        return { needsPasskey: true };
                      }
                      var sid = twoFactorSessionIdOf(auth);
                      if (sid) {
                        ctx.pending2fa = { sessionID: sid };
                        return { needs2FA: true };
                      }
                      if (
                        (!auth.token && !auth.encryptedToken) ||
                        !auth.keyAttributes
                      ) {
                        throw new Error("bad_auth_response");
                      }
                      return finishLoginInternal(s, ctx, auth, false);
                    });
                  });
                });
            });
        });
    },

    // 第三步（2FA）：TOTP 验证码。SRP 路径（有 kek）直接解 token 完成登录；
    // OTP 登录路径（无 kek）按响应分流（输密码解锁 / passkey / 设密码）。
    loginTotp: function (a) {
      if (!loginCtx || !loginCtx.pending2fa) {
        throw new Error("no_login_ctx");
      }
      var ctx = loginCtx;
      return apiAnon("/users/two-factor/verify", {
        method: "POST",
        body: JSON.stringify({
          sessionID: ctx.pending2fa.sessionID,
          code: String(a.code || "").trim(),
        }),
      }).then(function (res) {
        if (res.status === 401) throw new Error("incorrect_code");
        if (res.status === 404 || res.status === 410) {
          throw new Error("session_expired");
        }
        if (res.status === 429) throw new Error("rate_limited");
        if (!res.ok) throw new Error("http_" + res.status);
        return res.json().then(function (auth) {
          return sodium().then(function (s) {
            if (ctx.kek) ctx.usedTwoFactor = true;
            return classifyAuthResponse(s, ctx, auth, true);
          });
        });
      });
    },

    // ---- 邮箱 OTP 登录 / 原生注册 / passkey ----

    // 发送一次性验证码（POST /users/ott）。purpose: "login" | "signup"。
    // 同邮箱保留已有 loginCtx（含 SRP 属性/kek），否则新建。
    sendOtt: function (a) {
      var email = String(a.email || "").trim();
      var purpose = a.purpose === "signup" ? "signup" : "login";
      if (!email) throw new Error("bad_email");
      return apiAnon("/users/ott", {
        method: "POST",
        body: JSON.stringify({ email: email, purpose: purpose }),
      }).then(function (res) {
        if (res.ok) {
          if (!loginCtx || loginCtx.email !== email) {
            loginCtx = {
              email: email,
              srpAttrs: null,
              kek: null,
              pending2fa: null,
              ottPurpose: purpose,
              otpAuth: null,
              passkey: null,
              signupKeys: null,
              usedTwoFactor: false,
            };
          } else {
            loginCtx.ottPurpose = purpose;
            loginCtx.pending2fa = null;
            loginCtx.otpAuth = null;
            loginCtx.passkey = null;
          }
          return { sent: true };
        }
        return apiErrorCode(res).then(function (code) {
          if (res.status === 429) throw new Error("rate_limited");
          if (code === "USER_NOT_REGISTERED") throw new Error("not_registered");
          if (code === "USER_ALREADY_REGISTERED") {
            throw new Error("already_registered");
          }
          if (code === "USER_SIGNUP_INCOMPLETE") {
            throw new Error("signup_incomplete");
          }
          throw new Error("http_" + res.status + (code ? ":" + code : ""));
        });
      });
    },

    // 验证邮箱验证码（POST /users/verify-email）。注册路径要求裸 token 响应
    // （Signup::verified），登录路径按 classifyAuthResponse 分流。
    verifyOtt: function (a) {
      if (!loginCtx) throw new Error("no_login_ctx");
      var ctx = loginCtx;
      var code = String(a.code || "").trim();
      if (!code) throw new Error("bad_code");
      return apiAnon("/users/verify-email", {
        method: "POST",
        body: JSON.stringify({ email: ctx.email, ott: code }),
      }).then(function (res) {
        if (res.status === 401) throw new Error("incorrect_code");
        if (res.status === 410) throw new Error("code_expired");
        if (res.status === 429) throw new Error("rate_limited");
        if (!res.ok) throw new Error("http_" + res.status);
        return res.json().then(function (auth) {
          return sodium().then(function (s) {
            if (ctx.ottPurpose === "signup") {
              if (
                auth.keyAttributes ||
                auth.encryptedToken ||
                twoFactorSessionIdOf(auth) ||
                auth.passkeySessionID
              ) {
                throw new Error("already_registered");
              }
              if (!auth.token) throw new Error("bad_auth_response");
              ctx.otpAuth = auth;
              return { next: "setpassword" };
            }
            return classifyAuthResponse(s, ctx, auth, false);
          });
        });
      });
    },

    // OTP 登录后输密码解锁：用 keyAttributes 派生 kek 解密 master key 完成登录。
    // kek 同样由原生层派生后以 kekB64 传入（kdf 参数见 classifyAuthResponse 的 unlock 分流）
    unlockWithPassword: function (a) {
      if (!loginCtx || !loginCtx.otpAuth || !loginCtx.otpAuth.keyAttributes) {
        throw new Error("no_login_ctx");
      }
      var ctx = loginCtx;
      var auth = ctx.otpAuth;
      var kA = auth.keyAttributes;
      return sodium().then(function (s) {
        var kek = b64d(String(a.kekB64 || ""));
        if (kek.length !== 32) throw new Error("bad_kek");
        var masterKey;
        try {
          masterKey = s.crypto_secretbox_open_easy(
            b64d(kA.encryptedKey),
            b64d(kA.keyDecryptionNonce),
            kek,
          );
        } catch (e) {
          throw new Error("incorrect_password");
        }
        ctx.kek = kek;
        ctx.otpAuth = null;
        return finishLoginInternal(s, ctx, auth, ctx.usedTwoFactor === true);
      });
    },

    // 查询 passkey 验证进度：400=仍在等待；200=验证完成的 AuthResponse
    passkeyStatus: function () {
      if (!loginCtx || !loginCtx.passkey) throw new Error("no_login_ctx");
      var ctx = loginCtx;
      return apiAnon(
        "/users/two-factor/passkeys/get-token?sessionID=" +
          encodeURIComponent(ctx.passkey.sessionID),
      ).then(function (res) {
        if (res.status === 400) return { verified: false };
        if (res.status === 404 || res.status === 410) {
          throw new Error("session_expired");
        }
        if (!res.ok) throw new Error("http_" + res.status);
        return res.json().then(function (auth) {
          return sodium().then(function (s) {
            return classifyAuthResponse(
              s,
              ctx,
              auth,
              ctx.usedTwoFactor === true,
            );
          });
        });
      });
    },

    // passkey 验证页地址（与 rust build_passkey_verification_url 一致，参数均 urlencode）
    passkeyVerifyUrl: function () {
      if (!loginCtx || !loginCtx.passkey) throw new Error("no_login_ctx");
      var pk = loginCtx.passkey;
      var base = String(pk.accountsUrl || "https://accounts.ente.com").replace(
        /\/+$/,
        "",
      );
      var url =
        base +
        "/passkeys/verify?passkeySessionID=" +
        encodeURIComponent(pk.sessionID) +
        "&redirect=" +
        encodeURIComponent("https://auth.ente.com/passkeys/finish") +
        "&clientPackage=" +
        encodeURIComponent(PKG);
      return { url: url, totpAvailable: !!pk.totp2FASessionID };
    },

    // 注册密钥生成（对应 rust Signup::prepare）：kek/kekSalt 由原生层
    // （taskpool Argon2id，官方移动端参数阶梯 256MiB/16 → 128MiB/32）派生后传入，
    // 生成 masterKey/recoveryKey/secretKey 与 SRP 参数，返回恢复密钥助记词
    signupPrepare: function (a) {
      if (!loginCtx || !loginCtx.otpAuth || !loginCtx.otpAuth.token) {
        throw new Error("no_login_ctx");
      }
      var ctx = loginCtx;
      var kekSaltB64 = String(a.kekSaltB64 || "");
      var kekB64 = String(a.kekB64 || "");
      var opsLimit = Number(a.opsLimit);
      var memLimit = Number(a.memLimit);
      var kekSalt = b64d(kekSaltB64);
      var kek = b64d(kekB64);
      if (
        kek.length !== 32 ||
        kekSalt.length < 8 ||
        !isFinite(opsLimit) ||
        !isFinite(memLimit) ||
        opsLimit < 1 ||
        memLimit < 134217728
      ) {
        throw new Error("bad_kdf_params");
      }
      return sodium().then(function (s) {
        return apiAnon("/users/session-validity/v2", {
          token: ctx.otpAuth.token,
        })
          .then(function (res) {
            if (!res.ok) throw new Error("http_" + res.status);
            return res.json();
          })
          .then(function (v) {
            var remote = v || {};
            if (remote.hasSetKeys === true || remote.keyAttributes) {
              throw new Error("already_registered");
            }
            var masterKey = s.randombytes_buf(32);
            var recoveryKey = s.randombytes_buf(32);
            var secretKey = s.randombytes_buf(s.crypto_box_SECRETKEYBYTES);
            var publicKey = s.crypto_scalarmult_base(secretKey);
            var loginKey = s.crypto_kdf_derive_from_key(32, 1, "loginctx", kek)
              .subarray(0, 16);
            function box(pt, key) {
              var n = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
              var c = s.crypto_secretbox_easy(pt, n, key);
              return { c: b64e(c), n: b64e(n) };
            }
            var encKey = box(masterKey, kek);
            var encSecretKey = box(secretKey, masterKey);
            var encMkWithRk = box(masterKey, recoveryKey);
            var encRkWithMk = box(recoveryKey, masterKey);
            var keyAttributes = {
              kekSalt: kekSaltB64,
              encryptedKey: encKey.c,
              keyDecryptionNonce: encKey.n,
              publicKey: b64e(publicKey),
              encryptedSecretKey: encSecretKey.c,
              secretKeyDecryptionNonce: encSecretKey.n,
              memLimit: memLimit,
              opsLimit: opsLimit,
              masterKeyEncryptedWithRecoveryKey: encMkWithRk.c,
              masterKeyDecryptionNonce: encMkWithRk.n,
              recoveryKeyEncryptedWithMasterKey: encRkWithMk.c,
              recoveryKeyDecryptionNonce: encRkWithMk.n,
            };
            var srpUserID = uuidV4();
            var srpSalt = s.randombytes_buf(16);
            ctx.kek = kek;
            ctx.signupKeys = {
              keyAttributes: keyAttributes,
              srpUserID: srpUserID,
              srpSaltB64: b64e(srpSalt),
              loginKey: loginKey,
              verifierB64: null,
              mnemonic: null,
            };
            return srpVerifierOf(enc.encode(srpUserID), srpSalt, loginKey).then(
              function (verifier) {
                ctx.signupKeys.verifierB64 = b64e(verifier);
                return mnemonicOf(s, recoveryKey).then(function (mnemonic) {
                  ctx.signupKeys.mnemonic = mnemonic;
                  return { mnemonic: mnemonic };
                });
              },
            );
          });
      });
    },

    // 注册收尾（对应 rust complete_signup）：幂等上传 keyAttributes →
    // SRP setup/complete（400=已配置容忍跳过）→ 校验远端 SRP 属性 → 持久化会话
    signupFinish: function () {
      if (
        !loginCtx ||
        !loginCtx.signupKeys ||
        !loginCtx.otpAuth ||
        !loginCtx.otpAuth.token
      ) {
        throw new Error("no_login_ctx");
      }
      var ctx = loginCtx;
      var keys = ctx.signupKeys;
      var token = ctx.otpAuth.token;
      return sodium().then(function (s) {
        return apiAnon("/users/session-validity/v2", { token: token })
          .then(function (res) {
            if (!res.ok) throw new Error("http_" + res.status);
            return res.json();
          })
          .then(function (v) {
            var remote = v || {};
            var ra = remote.keyAttributes;
            if (remote.hasSetKeys === true || ra) {
              var ka = keys.keyAttributes;
              var same =
                ra &&
                ra.kekSalt === ka.kekSalt &&
                ra.encryptedKey === ka.encryptedKey &&
                ra.publicKey === ka.publicKey;
              if (!same) throw new Error("already_registered");
              return null;
            }
            return apiAnon("/users/attributes", {
              method: "PUT",
              token: token,
              body: JSON.stringify({ keyAttributes: keys.keyAttributes }),
            }).then(function (res) {
              if (!res.ok) throw new Error("http_" + res.status);
              return null;
            });
          })
          .then(function () {
            var aPrivBig = bytesToBig(s.randombytes_buf(64));
            var aPubBig = modpow(5n, aPrivBig, SRP_N);
            var srpA = b64e(pad512(bigToBytes(aPubBig)));
            return apiAnon("/users/srp/setup", {
              method: "POST",
              token: token,
              body: JSON.stringify({
                srpUserID: keys.srpUserID,
                srpSalt: keys.srpSaltB64,
                srpVerifier: keys.verifierB64,
                srpA: srpA,
              }),
            }).then(function (res) {
              if (res.status === 400) return null; // 已配置：容忍（与 rust 一致）
              if (!res.ok) throw new Error("http_" + res.status);
              return res.json().then(function (j) {
                if (!j || !j.setupID || !j.srpB) throw new Error("bad_setup");
                var serverB = b64d(j.srpB);
                return srpCompute(
                  aPrivBig,
                  enc.encode(keys.srpUserID),
                  b64d(keys.srpSaltB64),
                  keys.loginKey,
                  serverB,
                ).then(function (r) {
                  return apiAnon("/users/srp/complete", {
                    method: "POST",
                    token: token,
                    body: JSON.stringify({
                      setupID: String(j.setupID),
                      srpM1: b64e(r.m1),
                    }),
                  }).then(function (res2) {
                    if (!res2.ok) throw new Error("http_" + res2.status);
                    return res2.json().then(function (c) {
                      if (
                        !c ||
                        !c.srpM2 ||
                        !bytesEqual(b64dFlexible(c.srpM2), r.m2)
                      ) {
                        throw new Error("m2_mismatch");
                      }
                      return null;
                    });
                  });
                });
              });
            });
          })
          .then(function () {
            return apiAnon(
              "/users/srp/attributes?email=" + encodeURIComponent(ctx.email),
              { token: token },
            );
          })
          .then(function (res) {
            if (!res.ok) throw new Error("http_" + res.status);
            return res.json().then(function (j) {
              var at = j && j.attributes ? j.attributes : null;
              if (
                !at ||
                String(at.srpUserID) !== keys.srpUserID ||
                at.srpSalt !== keys.srpSaltB64 ||
                at.kekSalt !== keys.keyAttributes.kekSalt ||
                Number(at.memLimit) !== Number(keys.keyAttributes.memLimit) ||
                Number(at.opsLimit) !== Number(keys.keyAttributes.opsLimit)
              ) {
                throw new Error("srp_attributes_mismatch");
              }
              ctx.srpAttrs = at;
              var auth = {
                id: ctx.otpAuth.id,
                token: token,
                keyAttributes: keys.keyAttributes,
              };
              return finishLoginInternal(s, ctx, auth, false);
            });
          });
      });
    },

    // SRP 数学自检：官方 Go 服务端 golden vector（见 accounts crate srp.rs）
    srpSelfTest: function () {
      var identity = enc.encode("repro-user-id");
      var salt = enc.encode("0123456789abcdef");
      var loginKey = enc.encode("1234567890abcdef");
      var aPrivBig = bytesToBig(
        unhex(
          "0000000000000000000000000000000000000000000000000000000000000000" +
            "00000000000000000000000000000000000000000000000000000000000006de",
        ),
      );
      var EXPECT_M1 =
        "c0953b8c74d400fbf664a515deb700d73b65231e7e207a2e2326ff8cf70567ac";
      return srpInit()
        .then(function (k) {
          return sha256Cat(identity, new Uint8Array([0x3a]), loginKey).then(
            function (idH) {
              return sha256Cat(salt, idH).then(function (xH) {
                var x = bytesToBig(xH);
                var v = modpow(5n, x, SRP_N);
                var bPrivBig = bytesToBig(new Uint8Array(64).fill(0x42));
                var bPubBig =
                  (k * v + modpow(5n, bPrivBig, SRP_N)) % SRP_N;
                var serverB = bigToBytes(bPubBig);
                return srpCompute(aPrivBig, identity, salt, loginKey, serverB);
              });
            },
          );
        })
        .then(function (r) {
          var m1 = hexOf(r.m1);
          if (m1 !== EXPECT_M1) throw new Error("srp_self_test_failed:" + m1);
          return { ok: true };
        });
    },

    // 打开账户网页（修改密码等）前，确认网页端本地账户状态完整。
    // 官方 change-password 页依赖 localStorage.user 为完整 LocalUser（id/email/token）
    // 与 keyAttributes；缺失时会 stashRedirect 并跳回登录页，表现为闪一下登录页后一直转圈。
    ensureUser: function () {
      var u = null;
      try {
        u = JSON.parse(localStorage.getItem("user") || "null");
      } catch (e) {
        u = null;
      }
      if (!u || typeof u.email !== "string" || typeof u.id !== "number") {
        return { ready: false };
      }
      var hasKeys = false;
      try {
        var k = JSON.parse(localStorage.getItem("keyAttributes") || "null");
        hasKeys =
          !!(k && typeof k.encryptedKey === "string" && typeof k.kekSalt === "string");
      } catch (e) {
        hasKeys = false;
      }
      return readToken()
        .then(function (token) {
          if (!token) return { ready: false };
          // 保持 localStorage.user.token 与 IndexedDB 中的真实 token 一致
          if (u.token !== token) {
            u.token = token;
            try {
              localStorage.setItem("user", JSON.stringify(u));
            } catch (e) {}
          }
          return { ready: hasKeys };
        })
        .catch(function () {
          return { ready: false };
        });
    },

    // 退出登录：对齐官方 accountLogout。先注销远端会话，再删除本地 auth token
    // 并清空 sessionStorage / localStorage。
    // 只删 IndexedDB token 会留下 user / keyAttributes / srpAttributes 等“半登录”状态，
    // 下次登录会走错分支，提交密码后报“出错了”。
    logout: function () {
      // 先同步销毁本地会话：之后即使页面被原生侧导航打断，登录态也已经失效
      try {
        sessionStorage.clear();
      } catch (e) {}
      try {
        localStorage.clear();
      } catch (e) {}
      // 标记“已主动退出”：文档启动注入脚本据此不再恢复旧会话
      try {
        localStorage.setItem("__enteSignedOut", "1");
      } catch (e) {}
      cache = {};
      loginCtx = null;

      function remoteLogout() {
        return new Promise(function (resolve) {
          var timer = setTimeout(function () {
            resolve(false);
          }, 5000);
          api("/users/logout", { method: "POST" })
            .then(function (res) {
              clearTimeout(timer);
              resolve(res.ok || res.status === 401);
            })
            .catch(function () {
              clearTimeout(timer);
              resolve(false);
            });
        });
      }

      function removeToken() {
        return new Promise(function (resolve) {
          var timer = setTimeout(resolve, 3000);
          function finish() {
            clearTimeout(timer);
            resolve();
          }
          try {
            var req = indexedDB.open("kv", 1);
            req.onupgradeneeded = function () {
              try {
                req.result.createObjectStore("kv");
              } catch (e) {}
            };
            req.onsuccess = function () {
              var db = req.result;
              try {
                var tx = db.transaction("kv", "readwrite");
                tx.objectStore("kv").delete("token");
                tx.oncomplete = function () {
                  try {
                    db.close();
                  } catch (e) {}
                  finish();
                };
                tx.onerror = function () {
                  try {
                    db.close();
                  } catch (e) {}
                  finish();
                };
                tx.onabort = function () {
                  try {
                    db.close();
                  } catch (e) {}
                  finish();
                };
              } catch (e) {
                try {
                  db.close();
                } catch (e2) {}
                finish();
              }
            };
            req.onerror = function () {
              finish();
            };
          } catch (e) {
            finish();
          }
        });
      }

      // 远端注销不阻塞本地退出（慢网络下页面随时可能被原生侧导航走）
      remoteLogout();
      return removeToken().then(function () {
        return true;
      });
    },

    // ---- 导出 / 导入加密文件（与官方 EnteAuthExport 格式一致：Argon2id + secretbox） ----

    encryptExport: function (a) {
      return sodium().then(function (s) {
        var salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
        var ops = s.crypto_pwhash_OPSLIMIT_INTERACTIVE;
        var mem = s.crypto_pwhash_MEMLIMIT_INTERACTIVE;
        var key = s.crypto_pwhash(
          s.crypto_secretbox_KEYBYTES,
          enc.encode(a.password || ""),
          salt,
          ops,
          mem,
          s.crypto_pwhash_ALG_ARGON2ID13,
        );
        var nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
        var ct = s.crypto_secretbox_easy(enc.encode(a.plain || ""), nonce, key);
        return {
          version: 1,
          kdfParams: { memLimit: mem, opsLimit: ops, salt: b64e(salt) },
          encryptedData: b64e(ct),
          encryptionNonce: b64e(nonce),
        };
      });
    },

    decryptExport: function (a) {
      return sodium().then(function (s) {
        var j = typeof a.file === "string" ? JSON.parse(a.file) : a.file;
        var k = j.kdfParams;
        var key = s.crypto_pwhash(
          s.crypto_secretbox_KEYBYTES,
          enc.encode(a.password || ""),
          b64d(k.salt),
          k.opsLimit,
          k.memLimit,
          s.crypto_pwhash_ALG_ARGON2ID13,
        );
        var pt = s.crypto_secretbox_open_easy(
          b64d(j.encryptedData),
          b64d(j.encryptionNonce),
          key,
        );
        return dec.decode(pt);
      });
    },

    // 校验用：用 Web Crypto 独立计算 TOTP，与原生实现比对
    webTotp: function (a) {
      var key = base32decode(a.secret);
      var msg = new Uint8Array(8);
      var c = a.step;
      for (var i = 7; i >= 0; i--) {
        msg[i] = c & 0xff;
        c = Math.floor(c / 256);
      }
      var hash =
        a.algorithm === "sha256" ? "SHA-256" : a.algorithm === "sha512" ? "SHA-512" : "SHA-1";
      return crypto.subtle
        .importKey("raw", key, { name: "HMAC", hash: hash }, false, ["sign"])
        .then(function (k) {
          return crypto.subtle.sign("HMAC", k, msg);
        })
        .then(function (sig) {
          var h = new Uint8Array(sig);
          var off = h[h.length - 1] & 0x0f;
          var bin =
            ((h[off] & 0x7f) << 24) |
            (h[off + 1] << 16) |
            (h[off + 2] << 8) |
            h[off + 3];
          bin = bin >>> 0;
          if (a.type === "steam") {
            var steam = "23456789BCDFGHJKMNPQRTVWXY";
            var v = bin;
            var s = "";
            for (var j = 0; j < 5; j++) {
              s += steam.charAt(v % steam.length);
              v = Math.floor(v / steam.length);
            }
            return s;
          }
          var m = Math.pow(10, a.digits);
          var out = (bin % m).toString();
          while (out.length < a.digits) out = "0" + out;
          return out;
        });
    },
  };

  function base32decode(input) {
    var alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var s = input.replace(/\s+/g, "").replace(/-/g, "").toUpperCase();
    var bits = 0;
    var value = 0;
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var idx = alpha.indexOf(s.charAt(i));
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

  // ---------- 命令队列 ----------

  var queue = [];

  function pushResult(seq, op, okk, data, error) {
    queue.push({
      seq: seq,
      op: op,
      ok: okk,
      payload: okk ? JSON.stringify(data === undefined ? null : data) : "",
      error: error || "",
    });
    if (queue.length > 80) queue.shift();
  }

  function cmd(json) {
    var c;
    try {
      c = JSON.parse(json);
    } catch (e) {
      pushResult(0, "?", false, null, "bad_cmd");
      return "ok";
    }
    var seq = c.seq;
    var op = c.op;
    console.info("enteExt cmd seq=" + seq + " op=" + op + " args=" + JSON.stringify(c.args || {}).slice(0, 300));
    var fn = OPS[op];
    if (!fn) {
      pushResult(seq, op, false, null, "unknown_op:" + op);
      return "ok";
    }
    Promise.resolve()
      .then(function () {
        return fn(c.args || {});
      })
      .then(function (data) {
        console.info("enteExt cmd ok seq=" + seq + " op=" + op);
        pushResult(seq, op, true, data, "");
      })
      .catch(function (e) {
        var msg = (e && e.message) || String(e);
        console.error("enteExt op failed seq=" + seq + " op=" + op + " error=" + msg + " stack=" + (e && e.stack ? String(e.stack).slice(0, 600) : ""));
        pushResult(seq, op, false, null, msg);
      });
    return "ok";
  }

  function probeState() {
    var keys = [];
    try {
      for (var i = 0; i < sessionStorage.length; i++) {
        keys.push(sessionStorage.key(i));
      }
    } catch (e) {
      keys.push("err:" + e.message);
    }
    return {
      version: 1,
      sodiumReady: !!(window.sodium && window.sodium.crypto_secretbox_easy),
      hasSessionKey: !!sessionStorage.getItem("encryptionKey"),
      sessionKeys: keys,
      host: location.host,
      path: location.pathname,
      cached: Object.keys(cache).length,
      loginCtxReady: !!loginCtx,
      email: (function () {
        try {
          var u = JSON.parse(localStorage.getItem("user") || "null");
          return u && u.email ? u.email : "";
        } catch (e) {
          return "";
        }
      })(),
    };
  }

  var ext = {
    version: 2,
    cmd: cmd,

    // 原生轮询入口：返回探针状态 + 已完成的命令结果（取走后清空）
    poll: function () {
      var rs = queue;
      queue = [];
      return JSON.stringify({ probe: probeState(), results: rs });
    },

    probe: function () {
      return JSON.stringify(probeState());
    },

    getSessionKey: function () {
      return sessionStorage.getItem("encryptionKey") || "";
    },

    // 诊断用：列出 localStorage 键与 kv 库中的 key / token 形状
    dump: function () {
      var out = { ls: [], idb: null };
      try {
        for (var i = 0; i < localStorage.length; i++) {
          out.ls.push(localStorage.key(i));
        }
      } catch (e) {
        out.lsErr = e.message;
      }
      var p = new Promise(function (resolve) {
        var req = indexedDB.open("kv", 1);
        req.onupgradeneeded = function () {
          req.result.createObjectStore("kv");
        };
        req.onsuccess = function () {
          var db = req.result;
          try {
            var st = db.transaction("kv", "readonly").objectStore("kv");
            var kr = st.getAllKeys();
            kr.onsuccess = function () {
              var tr = st.get("token");
              tr.onsuccess = function () {
                var v = tr.result;
                db.close();
                out.idb = {
                  keys: kr.result,
                  tokenType: typeof v,
                  tokenLen: typeof v === "string" ? v.length : null,
                };
                resolve(out);
              };
              tr.onerror = function () {
                db.close();
                out.idbErr = "get:" + tr.error;
                resolve(out);
              };
            };
            kr.onerror = function () {
              db.close();
              out.idbErr = "keys:" + kr.error;
              resolve(out);
            };
          } catch (e) {
            db.close();
            out.idbErr = e.message;
            resolve(out);
          }
        };
        req.onerror = function () {
          out.idbErr = String(req.error);
          resolve(out);
        };
      });
      p.then(function (o) {
        pushResult(0, "dump", true, o, "");
      });
      return "ok";
    },

    reload: function () {
      location.reload();
      return "ok";
    },
  };

  Object.defineProperty(window, "__enteExt", {
    value: ext,
    writable: false,
    enumerable: false,
    configurable: false,
  });

  // 登录成功后 web 端会先渲染自己的首页，再由原生壳切到原生列表。
  // 这里在路由切到已登录首页的瞬间把页面涂成启动图底色并隐藏，
  // 避免短暂闪出网页端首页。
  (function installHomeFlashGuard() {
    try {
      if (window.__enteHomeGuard) return;
      window.__enteHomeGuard = true;
      // 账户页（修改密码）成功后网页会跳到 /auth，此时不应再遮挡首页
      try {
        if (location.pathname !== "/change-password") {
          sessionStorage.removeItem("__enteAccountPage");
        }
      } catch (e) {}
      var check = function () {
        try {
          // 官方 auth 应用登录后的首页路由是 /auth（appHomeRoute），根路径会无条件跳登录页
          var p = location.pathname;
          var home = p === "/" || p === "/index" || p === "/auth";
          if (home && sessionStorage.getItem("__enteAccountPage")) return;
          if (home && sessionStorage.getItem("encryptionKey")) {
            var d = document.documentElement;
            d.style.background = "#A75CFF";
            d.style.visibility = "hidden";
          }
        } catch (e) {}
      };
      var wrap = function (name) {
        var orig = history[name];
        history[name] = function () {
          var r = orig.apply(this, arguments);
          check();
          return r;
        };
      };
      wrap("pushState");
      wrap("replaceState");
      window.addEventListener("popstate", check);
    } catch (e) {}
  })();

  // 直板手机横屏时（视口宽 640-1023 且高 ≤520），官方登录壳层的"平板带"布局
  // 会用 268px 高的品牌横幅占掉整个屏幕高度，把表单挤成一条约 60px 的窄缝；
  // 且壳层固定 100svh + overflow:hidden，滚动只发生在内部小容器里，
  // 软键盘弹出时几乎无法操作。此模式下隐藏品牌横幅，并把壳层改造成
  // 普通文档流（高度 auto、不裁切），整页（html 级）滚动，保证横屏能完成
  // 登录/注册输入；竖屏（<640）与真平板（≥1024，桌面分栏布局）不受影响。
  (function installShortViewportFix() {
    try {
      if (window.__enteShortViewportFix) return;
      window.__enteShortViewportFix = true;
      var css =
        ".ext-short-viewport main{padding:0 !important;height:auto !important;min-height:100svh !important;overflow:visible !important;}" +
        ".ext-short-viewport main>div{border-radius:0 !important;height:auto !important;min-height:100svh !important;overflow:visible !important;}" +
        ".ext-short-viewport main>div>div{display:none !important;}" +
        ".ext-short-viewport main>div>section{margin-top:0 !important;border-radius:0 !important;flex:none !important;height:auto !important;overflow:visible !important;padding:16px 32px 32px !important;}" +
        ".ext-short-viewport main>div>section>div{max-width:440px;margin-left:auto;margin-right:auto;}";
      var style = null;
      // 注入时机在 document start：head/documentElement 可能都还不存在，
      // 样式注入必须惰性化，且任何一步失败都不能阻断后续事件重试
      var ensureStyle = function () {
        try {
          if (style && style.parentNode) return;
          var el = document.createElement("style");
          el.textContent = css;
          (document.head || document.documentElement).appendChild(el);
          style = el;
        } catch (e) {}
      };
      var lastW = -1;
      var lastH = -1;
      var apply = function () {
        try {
          ensureStyle();
          var w = window.innerWidth;
          var h = window.innerHeight;
          if (w === lastW && h === lastH) return;
          lastW = w;
          lastH = h;
          var short = w >= 640 && w < 1024 && h <= 520;
          document.documentElement.classList.toggle("ext-short-viewport", short);
        } catch (e) {}
      };
      // 先注册事件再首跑：即使首次 apply 抛错，旋转/加载事件仍能重试
      window.addEventListener("resize", apply);
      window.addEventListener("orientationchange", apply);
      document.addEventListener("DOMContentLoaded", apply);
      if (window.visualViewport) {
        window.visualViewport.addEventListener("resize", apply);
      }
      // ArkWeb 旋转时不一定派发 resize/orientationchange：用 matchMedia 变更
      // 监听 + 轻量轮询兜底，仅在尺寸真正变化时重算
      try {
        var mqs = [window.matchMedia("(min-width: 640px)"),
          window.matchMedia("(min-width: 1024px)"),
          window.matchMedia("(max-height: 520px)")];
        for (var i = 0; i < mqs.length; i++) {
          if (mqs[i].addEventListener) {
            mqs[i].addEventListener("change", apply);
          } else if (mqs[i].addListener) {
            mqs[i].addListener(apply);
          }
        }
      } catch (e) {}
      window.setInterval(apply, 400);
      apply();
    } catch (e) {}
  })();
})();
