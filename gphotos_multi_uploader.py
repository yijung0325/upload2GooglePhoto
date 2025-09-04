#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Google Photos 多帳號批次上傳器（零參數可跑 + 預設把成功上傳的照片丟到資源回收桶）

預設
- root = ~/Pictures/Google
- config = ./gphotos_routes.json（若不存在，自動掃描 credentials_*.json 產生）
- 只操作「App 建立」相簿；找不到就自動建立（不加尾綴）
- 最小權限：appendonly + readonly.appcreateddata
- 上傳成功（該帳號+相簿名整組 FAIL=0）後，把「成功上傳的照片」移到 OS 資源回收桶（影片不動）
- 想保留本機檔：加 --no-trash

需求：requests、google-auth-oauthlib、google-auth、send2trash
"""

import sys, json, time, argparse, re
from pathlib import Path
from typing import Dict, Optional, List, Any, Tuple

import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# 可選依賴：send2trash
try:
    from send2trash import send2trash
except Exception:
    send2trash = None  # 未安裝時會提示

PHOTOS_API = "https://photoslibrary.googleapis.com"

ALLOWED_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".heic", ".heif", ".webp", ".bmp",
    ".tiff", ".tif", ".mp4", ".mov", ".m4v", ".avi"
}
PHOTO_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".heic", ".heif", ".webp", ".bmp",
    ".tiff", ".tif"
}

DEVICE_AUTH_ENDPOINT = "https://oauth2.googleapis.com/device/code"
TOKEN_ENDPOINT_DEFAULT = "https://oauth2.googleapis.com/token"

# ------------------------ 設定 ------------------------

def load_routes(config_path: Path) -> Dict[str, Any]:
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ERROR] 載入設定檔失敗：{config_path}；{e}")
        sys.exit(1)

def save_routes(config_path: Path, data: Dict[str, Any]) -> None:
    config_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[INIT] 已建立預設設定檔：{config_path}")

def auto_make_default_config(config_path: Path) -> Optional[Dict[str, Any]]:
    """掃描當前目錄 credentials_*.json 自動產生預設設定。"""
    creds = sorted(Path.cwd().glob("credentials_*.json"))
    if not creds:
        return None
    accounts = []
    for p in creds:
        name = p.stem.replace("credentials_", "", 1)
        if not name:
            continue
        accounts.append({
            "name": name,
            "credentials_file": str(p.name),
            "token_file": f"token_{name}.json"
        })
    if not accounts:
        return None
    default_cfg = {
        "route_mode": "first_dir_account",
        "strict_routing": True,
        "album": {
            "mode": "second_level",
            "flat": False,
            "suffix_if_conflict": None   # 不加尾綴
        },
        "accounts": accounts
    }
    save_routes(config_path, default_cfg)
    return default_cfg

def build_account_maps(config: Dict[str, Any]) -> Dict[str, Dict[str, Path]]:
    mp: Dict[str, Dict[str, Path]] = {}
    for acct in config.get("accounts", []):
        name = acct["name"]
        creds = Path(acct["credentials_file"]).expanduser().resolve()
        token = Path(acct.get("token_file", f"token_{name}.json")).expanduser().resolve()
        mp[name] = {"creds": creds, "token": token}
    return mp

# ------------------------ OAuth ------------------------

def _read_client_info(credentials_file: Path) -> Dict[str, str]:
    raw = json.loads(credentials_file.read_text(encoding="utf-8"))
    info = raw.get("installed") or raw.get("web") or raw.get("client") or {}
    return {
        "client_id": info.get("client_id"),
        "client_secret": info.get("client_secret"),
        "token_uri": info.get("token_uri", TOKEN_ENDPOINT_DEFAULT),
    }

def _device_authorize(credentials_file: Path, scopes: List[str]) -> Credentials:
    ci = _read_client_info(credentials_file)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    r = requests.post(
        DEVICE_AUTH_ENDPOINT,
        data={"client_id": ci["client_id"], "scope": " ".join(scopes)},
        headers=headers, timeout=30,
    )
    if r.status_code != 200:
        try:
            msg = r.json().get("error_description") or r.text
        except Exception:
            msg = r.text
        print("[ERROR] 取得裝置授權碼失敗：", r.status_code, msg)
        print("➡ 請確認使用『TVs and Limited Input devices』類型 OAuth client。")
        sys.exit(1)

    j = r.json()
    print("\n=== Device Authorization ===")
    print(f"請在任一裝置瀏覽器開啟：{j.get('verification_url') or j.get('verification_uri')}")
    print(f"輸入代碼：{j['user_code']}\n")

    payload = {
        "client_id": ci["client_id"],
        "device_code": j["device_code"],
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    }
    if ci.get("client_secret"):
        payload["client_secret"] = ci["client_secret"]

    interval = j.get("interval", 5)
    while True:
        time.sleep(interval)
        tr = requests.post(ci["token_uri"], data=payload, headers=headers, timeout=30)
        if tr.status_code == 200:
            tj = tr.json()
            return Credentials(
                token=tj["access_token"],
                refresh_token=tj.get("refresh_token"),
                token_uri=ci["token_uri"],
                client_id=ci["client_id"],
                client_secret=ci.get("client_secret"),
                scopes=scopes,
            )
        try:
            err = tr.json().get("error")
        except Exception:
            err = None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        print(f"[ERROR] 交換 token 失敗：{tr.status_code} {tr.text}")
        sys.exit(1)

def get_credentials(credentials_file: Path, token_file: Path,
                    auth_method: str, scopes: List[str]) -> Credentials:
    creds: Optional[Credentials] = None
    if token_file.exists():
        creds = Credentials.from_authorized_user_file(str(token_file), scopes)
        # 若既有 token 的 scopes 不足，強制重新授權
        if not getattr(creds, "scopes", None) or not set(scopes).issubset(set(creds.scopes)):
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None
        if not creds or not creds.valid:
            if not credentials_file.exists():
                print(f"[ERROR] 找不到 OAuth 憑證：{credentials_file}")
                sys.exit(1)
            if auth_method == "device":
                creds = _device_authorize(credentials_file, scopes)
            else:
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), scopes)
                creds = flow.run_local_server(port=0)
            token_file.write_text(creds.to_json(), encoding="utf-8")

    # 嘗試 refresh 一次確保 access token 反映最新 scopes
    if creds and creds.refresh_token:
        try:
            creds.refresh(Request())
            token_file.write_text(creds.to_json(), encoding="utf-8")
        except Exception:
            pass
    return creds

def auth_header(creds: Credentials) -> Dict[str, str]:
    return {"Authorization": f"Bearer {creds.token}"}

# ------------------------ Albums（只列 App 建立） ------------------------

def list_app_albums(creds: Credentials) -> Dict[str, str]:
    albums: Dict[str, str] = {}
    headers = auth_header(creds)
    url = f"{PHOTOS_API}/v1/albums"
    params = {"pageSize": 50, "excludeNonAppCreatedData": "true"}
    while True:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            try:
                print("[ERROR] list_app_albums:", r.status_code, r.json())
            except Exception:
                print("[ERROR] list_app_albums:", r.status_code, r.text)
            r.raise_for_status()
        data = r.json()
        for a in data.get("albums", []):
            albums[a["title"]] = a["id"]
        token = data.get("nextPageToken")
        if not token:
            break
        params["pageToken"] = token
    return albums

def ensure_album(creds: Credentials, album_title: str, cache: Dict[str, str],
                 suffix_if_conflict: Optional[str]) -> str:
    if album_title in cache:
        return cache[album_title]
    create_title = album_title if not suffix_if_conflict else f"{album_title}{suffix_if_conflict}"
    url = f"{PHOTOS_API}/v1/albums"
    headers = auth_header(creds)
    payload = {"album": {"title": create_title}}
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    album_id = r.json()["id"]
    cache[album_title] = album_id
    return album_id

# ------------------------ 上傳 ------------------------

def upload_bytes(creds: Credentials, file_path: Path, max_retries: int = 3) -> str:
    url = f"{PHOTOS_API}/v1/uploads"
    headers = {
        **auth_header(creds),
        "Content-type": "application/octet-stream",
        "X-Goog-Upload-File-Name": file_path.name,
        "X-Goog-Upload-Protocol": "raw",
    }
    data = file_path.read_bytes()
    for attempt in range(1, max_retries + 1):
        r = requests.post(url, headers=headers, data=data, timeout=120)
        if r.status_code == 200 and r.text:
            return r.text
        time.sleep(1.5 * attempt)
    r.raise_for_status()
    return ""

def batch_create_media_items(creds: Credentials,
                             items: List[Tuple[str, Path]],
                             album_id: Optional[str]) -> Tuple[int, List[str], List[int]]:
    """
    items: [(uploadToken, Path), ...]
    return: ok_count, fails(list of msg), success_indices(list of int)
    """
    if not items:
        return 0, [], []
    url = f"{PHOTOS_API}/v1/mediaItems:batchCreate"
    headers = auth_header(creds)
    payload = {"newMediaItems": [
        {"description": "", "simpleMediaItem": {"uploadToken": tok, "fileName": p.name}}
        for tok, p in items
    ]}
    if album_id:
        payload["albumId"] = album_id
    r = requests.post(url, headers=headers, json=payload, timeout=180)
    r.raise_for_status()
    res = r.json().get("newMediaItemResults", [])
    ok = 0
    fails: List[str] = []
    success_idx: List[int] = []
    for i, one in enumerate(res):
        status = one.get("status", {})
        code = status.get("code", 0)
        msg = status.get("message", "")
        if code == 0:
            ok += 1
            success_idx.append(i)
        else:
            fails.append(f"idx={i} code={code} msg={msg}")
    return ok, fails, success_idx

# ------------------------ 路由 / 相簿名稱 ------------------------

def decide_account(file_path: Path,
                   root: Path,
                   rules: List[Dict[str, Any]],
                   default_acct: Optional[str],
                   strict_routing: bool,
                   route_mode: str,
                   account_names: set) -> Optional[str]:
    rel = file_path.relative_to(root)
    rel_str = rel.as_posix()
    ext = file_path.suffix.lower()

    if route_mode == "first_dir_account":
        if rel.parts:
            first = rel.parts[0]
            if first in account_names:
                return first
        return None if strict_routing else default_acct

    for rule in rules:
        acct = rule.get("account")
        cond = rule.get("when", {})
        globs = cond.get("glob_any", [])
        regexes = cond.get("regex_any", [])
        exts = cond.get("ext_any", [])

        if globs:
            for g in globs:
                if rel.match(g):
                    return acct
        if regexes:
            for rpat in regexes:
                if re.search(rpat, rel_str):
                    return acct
        if exts:
            if ext in [e.lower() for e in exts]:
                return acct

    return None if strict_routing else default_acct

def is_media_file(p: Path, exts: Optional[set] = None) -> bool:
    exts = ALLOWED_EXTS if exts is None else exts
    return p.is_file() and (p.suffix.lower() in exts)

def walk_media(root: Path, recursive: bool = True, exts: Optional[set] = None) -> List[Path]:
    if recursive:
        return [p for p in root.rglob("*") if is_media_file(p, exts)]
    else:
        return [p for p in root.glob("*") if is_media_file(p, exts)]

def album_title_for(root: Path, file_path: Path, mode: str, flat: bool) -> str:
    rel = file_path.parent.relative_to(root)
    if flat or mode == "root_only":
        return root.name
    if mode == "first_level":
        return rel.parts[0] if rel.parts else root.name
    if mode == "second_level":
        if len(rel.parts) >= 2:
            return rel.parts[1]
        return rel.parts[0] if rel.parts else root.name
    if mode == "relative_full":
        return str(rel) if rel.parts else root.name
    return rel.parts[0] if rel.parts else root.name

# ------------------------ 回收桶 ------------------------

def move_to_trash(paths: List[Path]) -> int:
    if not paths:
        return 0
    if send2trash is None:
        print("[WARN] 未安裝 send2trash，略過移到資源回收桶。請先：pip install send2trash")
        return 0
    moved = 0
    for p in paths:
        try:
            send2trash(str(p))
            moved += 1
        except Exception as e:
            print(f"[WARN] 移到資源回收桶失敗：{p} → {e}")
    return moved

# ------------------------ 主流程 ------------------------

def main():
    parser = argparse.ArgumentParser(
        description="多帳號 Google Photos 上傳器（App 相簿 / 最小權限 / 批次 / 預設上傳後丟回收桶）"
    )
    parser.add_argument("root", nargs="?", default="~/Pictures/Google",
                        help="要上傳的根資料夾（其下為 <account>/<album>/...），預設 ~/Pictures/Google")
    parser.add_argument("--config", type=str, default="gphotos_routes.json",
                        help="路由設定檔(JSON)，預設 gphotos_routes.json（找不到會自動產生）")
    parser.add_argument("--ext-any", action="store_true", help="不限制副檔名（預設只上傳常見影像/影片）")
    parser.add_argument("--dry-run", action="store_true", help="試跑：列出帳號/相簿與預計上傳檔案（不真的上傳）")
    parser.add_argument("--batch-size", type=int, default=25, help="一次 batchCreate 的筆數（預設 25）")
    parser.add_argument("--auth-method", choices=["local-server", "device"], default="local-server",
                        help="首次授權方式：local-server（自動開瀏覽器）或 device（顯示網址+代碼）")
    parser.add_argument("--no-album", action="store_true", help="不要加入任何相簿；只上傳到 Library")
    parser.add_argument("--allow-create-with-full-scope", action="store_true",
                        help="追加 photoslibrary 完整權限（若建立相簿被 403 可開此旗標重新授權）")
    parser.add_argument("--no-trash", action="store_true",
                        help="不要把成功上傳的『照片』移到資源回收桶（預設會移動）")
    args = parser.parse_args()

    base_scopes = [
        "https://www.googleapis.com/auth/photoslibrary.appendonly",
        "https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata",
    ]
    scopes = base_scopes + (["https://www.googleapis.com/auth/photoslibrary"] if args.allow_create_with_full_scope else [])

    # 讀/產設定檔
    config_path = Path(args.config).expanduser().resolve()
    if not config_path.exists():
        cfg = auto_make_default_config(config_path)
        if cfg is None:
            print("[ERROR] 找不到設定檔，且無法自動產生（當前資料夾沒有 credentials_*.json）")
            print("➡ 請放入 credentials_*.json 或自行建立 gphotos_routes.json 再重試。")
            sys.exit(1)
        config = cfg
    else:
        config = load_routes(config_path)

    route_mode = config.get("route_mode", "first_dir_account")
    strict_routing = bool(config.get("strict_routing", True))
    default_account = config.get("default_account")
    album_cfg = config.get("album", {})
    album_mode = album_cfg.get("mode", "second_level")
    album_flat = album_cfg.get("flat", False)
    album_suffix = album_cfg.get("suffix_if_conflict", None)  # 預設不加尾綴

    account_maps = build_account_maps(config)
    account_names = set(account_maps.keys())

    if not strict_routing and default_account and default_account not in account_maps:
        print(f"[ERROR] default_account={default_account} 未在 accounts 中定義")
        sys.exit(1)

    root = Path(args.root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"[ERROR] 路徑無效：{root}")
        sys.exit(1)

    rules = config.get("rules", [])
    exts = None if args.ext_any else ALLOWED_EXTS

    files = walk_media(root, recursive=not album_flat, exts=exts)
    if not files:
        print("[INFO] 找不到可上傳的媒體檔。")
        return

    # 規劃：先決定每個檔案的 (account, album_title)
    plan: Dict[Tuple[str, str], List[Path]] = {}
    for fp in files:
        acct = decide_account(
            fp, root, rules, default_acct=default_account, strict_routing=strict_routing,
            route_mode=route_mode, account_names=account_names
        )
        if not acct:
            print(f"[SKIP] 未命中任何帳號（strict or 無 default）：{fp.relative_to(root)}")
            continue
        album_title = album_title_for(root, fp, album_mode, album_flat)
        plan.setdefault((acct, album_title), []).append(fp)

    # dry-run：先完成 OAuth，列出計畫，不上傳
    if args.dry_run:
        seen_accounts = {acct for (acct, _alb) in plan.keys()}
        for acct in seen_accounts:
            paths = account_maps[acct]
            creds = get_credentials(paths["creds"], paths["token"], auth_method=args.auth_method, scopes=scopes)
            print(f"[AUTH] 帳號[{acct}] scopes={getattr(creds, 'scopes', [])} → token: {paths['token']}")
        for (acct, album_title), fps in plan.items():
            print(f"\n[DRY] 帳號[{acct}] 相簿「{album_title}」將上傳 {len(fps)} 個檔案：")
            for p in fps:
                print(f"  - {p.relative_to(root)}")
        print("\n[DRY] 試跑完成（未進行任何上傳）")
        return

    # 實際上傳
    creds_cache: Dict[str, Credentials] = {}
    album_cache: Dict[str, Dict[str, str]] = {}
    ok_total, fail_total = 0, 0
    batch_size = max(1, args.batch_size)
    trash_photos = (not args.no_trash)  # 預設 True

    for (acct, album_title), fps in plan.items():
        if acct not in creds_cache:
            paths = account_maps[acct]
            creds_cache[acct] = get_credentials(paths["creds"], paths["token"], auth_method=args.auth_method, scopes=scopes)
            print(f"[AUTH] 帳號[{acct}] scopes={getattr(creds_cache[acct], 'scopes', [])}")
            album_cache[acct] = list_app_albums(creds_cache[acct])  # 只列 App 相簿

        creds = creds_cache[acct]
        albums = album_cache[acct]

        # 決定 albumId（可選擇不上相簿）
        album_id = None
        if not args.no_album:
            try:
                album_id = albums.get(album_title) or ensure_album(creds, album_title, albums, album_suffix)
            except requests.HTTPError as e:
                if getattr(e, "response", None) is not None and e.response.status_code == 403:
                    print(f"[WARN] 帳號[{acct}] 相簿「{album_title}」建立/寫入被拒。改為只上傳到 Library。")
                    album_id = None
                else:
                    raise

        # 批次上傳 + 建立
        bucket: List[Tuple[str, Path]] = []
        success_photos: List[Path] = []  # 僅照片
        ok_cnt = fail_cnt = 0

        for p in fps:
            try:
                tok = upload_bytes(creds, p)
                bucket.append((tok, p))
                if len(bucket) >= batch_size:
                    ok, fails, succ_idx = batch_create_media_items(creds, bucket, album_id)
                    ok_cnt += ok; fail_cnt += len(fails)
                    for i in succ_idx:
                        sp = bucket[i][1]
                        if sp.suffix.lower() in PHOTO_EXTS:
                            success_photos.append(sp)
                    if fails:
                        for m in fails:
                            print(f"[FAIL][帳號 {acct} 相簿「{album_title if album_id else '(Library)'}」] {m}")
                    print(f"[BATCH] 帳號[{acct}] 相簿「{album_title if album_id else '(Library)'}」 送出 {ok + len(fails)} 筆 (OK {ok}, FAIL {len(fails)})")
                    bucket = []
            except Exception as e:
                fail_cnt += 1
                print(f"[ERROR] 上傳 {p.name}（帳號[{acct}] 相簿「{album_title if album_id else '(Library)'}」）失敗：{e}")

        if bucket:
            ok, fails, succ_idx = batch_create_media_items(creds, bucket, album_id)
            ok_cnt += ok; fail_cnt += len(fails)
            for i in succ_idx:
                sp = bucket[i][1]
                if sp.suffix.lower() in PHOTO_EXTS:
                    success_photos.append(sp)
            if fails:
                for m in fails:
                    print(f"[FAIL][帳號 {acct} 相簿「{album_title if album_id else '(Library)'}」] {m}")
            print(f"[BATCH-FINAL] 帳號[{acct}] 相簿「{album_title if album_id else '(Library)'}」 收尾送出 {ok + len(fails)} 筆 (OK {ok}, FAIL {len(fails)})")

        # 依預設把照片移到資源回收桶（僅在整組全數成功時）
        if trash_photos:
            if fail_cnt == 0:
                moved = move_to_trash(success_photos)
                print(f"[CLEANUP] 帳號[{acct}] 相簿「{album_title if album_id else '(Library)'}」：已將 {moved} 張照片移到資源回收桶。")
            else:
                print(f"[CLEANUP] 本組有失敗（FAIL={fail_cnt}），為保險不移到回收桶。")

        ok_total += ok_cnt; fail_total += fail_cnt
        print(f"[SUMMARY] 帳號[{acct}] 相簿「{album_title if album_id else '(Library)'}」 完成：OK {ok_cnt}, FAIL {fail_cnt}")

    print(f"\n完成。總計成功 {ok_total}，失敗 {fail_total}")

if __name__ == "__main__":
    main()

