"""
网易云NCM转MP3/FLAC工具
张一挥制作
人生苦短，我用Claude
"""
import struct
import json
import sys
import os
import base64
from pathlib import Path

# Enable Windows DPI awareness BEFORE any tkinter code runs
if sys.platform == "win32":
    import ctypes as _ctypes
    try:
        _ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per Monitor Aware V2
    except Exception:
        try:
            _ctypes.windll.shcore.SetProcessDpiAwareness(1)  # Per Monitor Aware
        except Exception:
            try:
                _ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

# AES-128 key for RC4 key decryption
AES_KEY = bytes.fromhex("687a4852416d736f356b496e62617857")  # "hzHRAmso5kInbaxW"
# AES-128 key for metadata decryption
AES_META_KEY = bytes.fromhex("2331346C6A6B5F215C5D2630553C2728")  # "#14ljk_!\\]&0U<'("


# ── Pure Python AES-128-ECB decryption ──────────────────────────────
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else ((a << 1) & 0xFF)


def _gmul(a: int, b: int) -> int:
    """Multiply two numbers in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _key_expansion(key: bytes) -> list[list[int]]:
    """AES-128 key expansion, returns 11 round keys (44 words)."""
    nk, nr = 4, 10
    w = []
    for i in range(nk):
        w.append(list(key[4 * i : 4 * i + 4]))

    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // nk - 1]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w


def _add_round_key(state: list[int], rk: list[int]):
    for i in range(16):
        state[i] ^= rk[i]


def _inv_sub_bytes(state: list[int]):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _inv_shift_rows(state: list[int]):
    # Row 1: shift right by 1
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    # Row 2: shift right by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift right by 3 (= left by 1)
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _inv_mix_columns(state: list[int]):
    for c in range(4):
        i = c * 4
        a, b, c_, d = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gmul(a, 0x0E) ^ _gmul(b, 0x0B) ^ _gmul(c_, 0x0D) ^ _gmul(d, 0x09)
        state[i + 1] = _gmul(a, 0x09) ^ _gmul(b, 0x0E) ^ _gmul(c_, 0x0B) ^ _gmul(d, 0x0D)
        state[i + 2] = _gmul(a, 0x0D) ^ _gmul(b, 0x09) ^ _gmul(c_, 0x0E) ^ _gmul(d, 0x0B)
        state[i + 3] = _gmul(a, 0x0B) ^ _gmul(b, 0x0D) ^ _gmul(c_, 0x09) ^ _gmul(d, 0x0E)


def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB decryption. Data must be padded to 16-byte blocks."""
    w = _key_expansion(key)
    result = bytearray()
    for blk_off in range(0, len(data), 16):
        state = list(data[blk_off : blk_off + 16])
        _add_round_key(state, sum(w[40:44], []))
        for rnd in range(9, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, sum(w[rnd * 4 : rnd * 4 + 4], []))
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, sum(w[0:4], []))
        result.extend(state)
    # PKCS7 unpad
    pad = result[-1]
    return bytes(result[:-pad])


def _word_array_from_bytes(data: bytes):
    """Convert bytes to list of 32-bit words (big-endian) used by CryptoJS."""
    padded = bytearray(data)
    words = []
    for i in range(0, len(padded), 4):
        chunk = padded[i : i + 4]
        while len(chunk) < 4:
            chunk.append(0)
        words.append(struct.unpack(">I", bytes(chunk))[0])
    return words


def _bytes_from_words(words: list[int], sig_bytes: int) -> bytes:
    """Convert list of 32-bit words back to bytes."""
    result = bytearray()
    for w in words:
        result.extend(struct.pack(">I", w))
    return bytes(result[:sig_bytes])


# ── NCM Decryption ──────────────────────────────────────────────────

def build_rc4_box(key: bytes) -> list[int]:
    """Build S-box from RC4 key (the actual decryption box used for audio)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (S[i] + j + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # Transform S into the decryption stream box
    result = [0] * 256
    for i in range(256):
        t = (i + 1) & 0xFF
        n = S[t]
        r = S[(t + n) & 0xFF]
        result[i] = S[(n + r) & 0xFF]
    return result


def detect_format(data: bytes) -> str:
    """Detect FLAC vs MP3 from magic bytes."""
    if len(data) >= 4 and data[:4] == b"fLaC":
        return "flac"
    return "mp3"


def decrypt_ncm(filepath: str | Path) -> dict | None:
    """
    Decrypt an NCM file. Returns dict with:
      status, musicName, artist, album, albumPic, format, audio_data
    """
    path = Path(filepath)
    if not path.exists():
        return {"status": False, "message": f"文件不存在: {filepath}"}

    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 16:
        return {"status": False, "message": "文件太小,不是有效的NCM文件"}

    magic1 = struct.unpack_from("<I", data, 0)[0]
    magic2 = struct.unpack_from("<I", data, 4)[0]

    if magic1 != 0x4E455443 or magic2 != 0x4D414446:
        return {"status": False, "message": "此文件不是有效的NCM文件"}

    offset = 10

    # Step 1: Read encrypted RC4 key data
    key_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    encrypted_key = bytes(b ^ 0x64 for b in data[offset : offset + key_len])
    offset += key_len

    # Step 2: AES-128-ECB decrypt to get RC4 key
    decrypted_key_block = aes_ecb_decrypt(encrypted_key, AES_KEY)
    rc4_key = decrypted_key_block[17:]  # Skip first 17 bytes (CryptoJS DER prefix)
    sbox = build_rc4_box(rc4_key)

    # Step 3: Read metadata (album art, song info)
    meta_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    metadata = {}
    album_pic = ""

    if meta_len > 0:
        encrypted_meta = bytes(b ^ 0x63 for b in data[offset : offset + meta_len])
        offset += meta_len

        # Metadata is base64-encoded, AES-encrypted JSON
        meta_base64 = bytes(encrypted_meta[22:]).decode("utf-8", errors="replace")
        try:
            encrypted_meta_json = base64.b64decode(meta_base64)
        except Exception:
            encrypted_meta_json = base64.b64decode(meta_base64 + "==")

        decrypted_meta_block = aes_ecb_decrypt(encrypted_meta_json, AES_META_KEY)
        meta_str = decrypted_meta_block[6:].decode("utf-8", errors="replace")
        # Strip trailing nulls and control chars
        meta_str = meta_str.rstrip("\x00").rstrip("\x08").rstrip("\x0b").rstrip("\x0c")

        try:
            metadata = json.loads(meta_str)
        except json.JSONDecodeError:
            metadata = {}

        album_pic = metadata.get("albumPic", "")

    # Step 4: Skip to audio data
    audio_offset = offset + struct.unpack_from("<I", data, offset + 5)[0] + 13
    encrypted_audio = bytearray(data[audio_offset:])

    # Step 5: Decrypt audio using S-box XOR
    for i in range(len(encrypted_audio)):
        encrypted_audio[i] ^= sbox[i & 0xFF]

    # Step 6: Detect format
    fmt = metadata.get("format")
    if not fmt:
        fmt = detect_format(encrypted_audio)

    # Build output filename: "artist(s) - title.fmt"
    artists = [a[0] for a in metadata.get("artist", [])] if isinstance(metadata.get("artist"), list) else []
    artist_str = " & ".join(artists) if artists else "未知歌手"
    title = metadata.get("musicName") or path.stem
    album = metadata.get("album", "")

    # Clean filename
    safe_name = f"{artist_str} - {title}.{fmt}"
    for ch in r'<>:"/\|?*':
        safe_name = safe_name.replace(ch, "_")

    return {
        "status": True,
        "title": title,
        "artist": artist_str,
        "album": album,
        "albumPic": album_pic,
        "format": fmt,
        "filename": safe_name,
        "audio_data": bytes(encrypted_audio),
    }


# ── Config ────────────────────────────────────────────────────────────

def _get_config_dir() -> Path:
    """Get config directory (hidden in AppData)."""
    appdata = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    p = Path(appdata) / "NCMConverter"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _get_config_path() -> Path:
    return _get_config_dir() / "config.json"


def load_config() -> dict:
    """Load saved config, return dict with at least 'output_dir'."""
    cfg = {"output_dir": ""}
    cfg_path = _get_config_path()
    if cfg_path.exists():
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict) and saved.get("output_dir"):
                cfg["output_dir"] = saved["output_dir"]
        except Exception:
            pass
    return cfg


def save_config(output_dir: str):
    """Save output_dir to config file."""
    cfg_path = _get_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump({"output_dir": output_dir}, f, ensure_ascii=False)


def get_output_dir() -> Path:
    """Get the current output directory (from config or default)."""
    cfg = load_config()
    if cfg["output_dir"]:
        p = Path(cfg["output_dir"])
        if p.exists():
            return p
    # Fallback: desktop or CWD
    desktop = Path.home() / "Desktop"
    default = (desktop if desktop.exists() else Path.cwd()) / "NCM_Output"
    return default


# ── GUI ─────────────────────────────────────────────────────────────

def convert_files(file_list: list[str], output_dir: Path, callback=None) -> tuple[int, int, list[str]]:
    """Convert a list of NCM files. Returns (success_count, fail_count, error_messages)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    success = 0
    fail = 0
    errors = []
    for filepath in file_list:
        fpath = Path(filepath.strip().strip('"'))
        if not fpath.exists():
            msg = f"文件不存在: {fpath.name}"
            errors.append(msg)
            if callback:
                callback(f"[错误] {msg}")
            fail += 1
            continue
        if fpath.suffix.lower() != ".ncm":
            continue  # Silently skip non-NCM files

        if callback:
            callback(f"处理: {fpath.name} ...", end="")

        result = decrypt_ncm(fpath)
        if not result["status"]:
            msg = result.get("message", "解密失败")
            errors.append(f"{fpath.name}: {msg}")
            if callback:
                callback(f"失败! {msg}")
            fail += 1
            continue

        out_path = output_dir / result["filename"]
        # Handle duplicate filenames
        if out_path.exists():
            stem, ext = out_path.stem, out_path.suffix
            counter = 1
            while out_path.exists():
                out_path = output_dir / f"{stem} ({counter}){ext}"
                counter += 1

        with open(out_path, "wb") as f:
            f.write(result["audio_data"])

        if callback:
            callback(f"完成! -> {out_path}")
            callback(f"  歌名: {result['title']} | 歌手: {result['artist']} | 格式: {result['format'].upper()}")
        success += 1

    return success, fail, errors


def pick_output_folder(parent) -> str | None:
    """Show folder picker dialog, returns path or None."""
    from tkinter import filedialog
    path = filedialog.askdirectory(
        parent=parent,
        title="选择音乐输出文件夹",
        initialdir=get_output_dir(),
    )
    if path:
        save_config(path)
    return path


def run_gui(initial_files: list[str] | None = None):
    """Launch GUI for settings and manual conversion."""
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    import threading

    # Use tkinterdnd2 Tk for proper Windows drag-and-drop support
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
        _dnd_available = True
    except Exception:
        root = tk.Tk()
        _dnd_available = False

    cfg = load_config()
    if cfg["output_dir"]:
        current_output = Path(cfg["output_dir"])
    else:
        current_output = Path.cwd() / "output"

    root.title("网易云NCM转MP3/FLAC工具 — 张一挥制作")
    root.geometry("600x800")
    root.minsize(500, 550)
    root.configure(bg="#F5F4F8")

    # ── Colors ──
    C_HEADER   = "#4A3DB8"
    C_PRIMARY  = "#5B4CC4"
    C_HOVER    = "#6C5DD3"
    C_DISABLED = "#A9A3D1"
    C_BG       = "#F5F4F8"
    C_CARD     = "#FFFFFF"
    C_TEXT     = "#1E1B2E"
    C_SUBTEXT  = "#6B6880"
    C_BORDER   = "#DFDCE8"
    C_DROP     = "#EEECF8"
    C_LOG_BG   = "#1E1D2B"
    C_LOG_FG   = "#BCC0D6"
    C_WHITE    = "#FFFFFF"

    # ── Fonts ──
    FONT_TITLE  = ("Microsoft YaHei", 14, "bold")
    FONT_HEADER = ("Microsoft YaHei", 11, "bold")
    FONT_BODY   = ("Microsoft YaHei", 10)
    FONT_SMALL  = ("Microsoft YaHei", 9)
    FONT_MONO   = ("Consolas", 9)
    FONT_BTN    = ("Microsoft YaHei", 12, "bold")

    # ── ttk style ──
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", font=FONT_BODY, padding=(16, 7))
    style.configure("TProgressbar", thickness=6, troughcolor=C_BORDER, background=C_PRIMARY)

    # ── HEADER ──
    header = tk.Frame(root, bg=C_HEADER, height=50)
    header.pack(fill=tk.X)
    header.pack_propagate(False)

    tk.Label(
        header, text="网易云 NCM 转 MP3 / FLAC",
        bg=C_HEADER, fg=C_WHITE, font=FONT_TITLE,
    ).pack(side=tk.LEFT, padx=22, pady=10)

    tk.Label(
        header, text="张一挥制作",
        bg=C_HEADER, fg="#B2ABE0", font=FONT_SMALL,
    ).pack(side=tk.RIGHT, padx=22, pady=14)

    # ── BOTTOM BAR (frame packed BEFORE body so it's never pushed off-screen) ──
    bottom = tk.Frame(root, bg=C_CARD, height=64)
    bottom.pack(fill=tk.X, side=tk.BOTTOM)
    bottom.pack_propagate(False)

    # ── BODY (packed AFTER bottom, fills the remaining middle space) ──
    body = tk.Frame(root, bg=C_BG)
    body.pack(fill=tk.BOTH, expand=True, padx=14, pady=(8, 0))

    # ── OUTPUT FOLDER ──
    tk.Label(body, text="输出目录", bg=C_BG, fg=C_SUBTEXT, font=FONT_SMALL).pack(anchor="w")

    folder_row = tk.Frame(body, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
    folder_row.pack(fill=tk.X, pady=(2, 8))

    folder_text = tk.Label(
        folder_row, text=str(current_output),
        bg=C_CARD, fg=C_TEXT, font=FONT_BODY, anchor="w",
        padx=14, pady=9,
    )
    folder_text.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def change_folder():
        path = pick_output_folder(root)
        if path:
            nonlocal current_output
            current_output = Path(path)
            folder_text.config(text=str(current_output))
            log(f"[设置] 输出目录已改为: {current_output}")

    ttk.Button(folder_row, text="更改文件夹", command=change_folder).pack(side=tk.RIGHT, padx=(0, 10), pady=7)

    # ── DROP ZONE ──
    drop_zone = tk.Frame(body, bg=C_DROP, highlightbackground=C_PRIMARY, highlightthickness=1, height=60)
    drop_zone.pack(fill=tk.X, pady=(0, 8))
    drop_zone.pack_propagate(False)

    drop_label = tk.Label(
        drop_zone,
        text="拖放 NCM 文件到此处\n或直接把文件拖到桌面图标上自动转换",
        bg=C_DROP, fg=C_PRIMARY,
        font=FONT_HEADER, justify="center",
    )
    drop_label.pack(expand=True)

    # ── TOOLBAR ──
    toolbar = tk.Frame(body, bg=C_BG)
    toolbar.pack(fill=tk.X, pady=(0, 4))

    file_list: list[str] = []

    def _add_paths(paths):
        """Add file paths to the list (used by both file dialog and DnD)."""
        added = False
        for p in paths:
            fpath = Path(p)
            if fpath.suffix.lower() == ".ncm" and p not in file_list:
                file_list.append(p)
                listbox.insert(tk.END, fpath.name)
                log(f"已添加: {fpath.name}")
                added = True
        return added

    def add_files():
        paths = filedialog.askopenfilenames(
            title="选择NCM文件",
            filetypes=[("NCM文件", "*.ncm"), ("所有文件", "*.*")],
        )
        _add_paths(paths)

    def remove_selected():
        for i in reversed(listbox.curselection()):
            listbox.delete(i)
            del file_list[i]

    def clear_all():
        listbox.delete(0, tk.END)
        file_list.clear()

    ttk.Button(toolbar, text="+ 添加文件", command=add_files).pack(side=tk.LEFT, padx=(0, 6))
    ttk.Button(toolbar, text="✕ 移除", command=remove_selected).pack(side=tk.LEFT, padx=(0, 6))
    ttk.Button(toolbar, text="清空", command=clear_all).pack(side=tk.LEFT)

    # ── LOG (pack BEFORE file list so it gets anchored to body bottom) ──
    log_frame = tk.Frame(body, bg=C_LOG_BG, highlightbackground=C_BORDER, highlightthickness=1, height=90)
    log_frame.pack(fill=tk.X, side=tk.BOTTOM)
    log_frame.pack_propagate(False)

    # ── FILE LIST (fills remaining space between toolbar and log) ──
    list_frame = tk.Frame(body, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
    list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 2))

    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = tk.Listbox(
        list_frame, yscrollcommand=scrollbar.set,
        font=FONT_BODY, selectmode=tk.EXTENDED, activestyle="none",
        bg=C_CARD, fg=C_TEXT,
        selectbackground=C_PRIMARY, selectforeground=C_WHITE,
        relief=tk.FLAT, highlightthickness=0, borderwidth=0,
    )
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2, pady=2)
    scrollbar.config(command=listbox.yview)

    if initial_files:
        for fp in initial_files:
            fpath = Path(fp.strip().strip('"'))
            if fpath.suffix.lower() == ".ncm":
                file_list.append(str(fpath))
                listbox.insert(tk.END, fpath.name)

    log_text = tk.Text(
        log_frame, font=FONT_MONO,
        bg=C_LOG_BG, fg=C_LOG_FG, insertbackground=C_LOG_FG,
        state=tk.DISABLED, wrap=tk.WORD,
        relief=tk.FLAT, padx=10, pady=4, borderwidth=0,
        height=4,
    )
    log_text.pack(fill=tk.BOTH, expand=True)

    def log(msg: str, end: str = "\n"):
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, msg + end)
        log_text.see(tk.END)
        log_text.config(state=tk.DISABLED)

    # ── BOTTOM BAR contents ──
    progress_frame = tk.Frame(bottom, bg=C_CARD)
    status_label = tk.Label(progress_frame, text="", bg=C_CARD, fg=C_SUBTEXT, font=FONT_SMALL)
    bar = ttk.Progressbar(progress_frame, mode="indeterminate", length=160)

    btn_frame = tk.Frame(bottom, bg=C_PRIMARY, cursor="hand2")
    btn_frame.pack(side=tk.RIGHT, padx=16, pady=9)

    btn_label = tk.Label(
        btn_frame, text="▶  开始转换",
        bg=C_PRIMARY, fg=C_WHITE, font=FONT_BTN,
        padx=32, pady=9,
    )
    btn_label.pack()

    def _btn_enter(_e=None):
        if btn_label.cget("bg") != C_DISABLED:
            btn_frame.configure(bg=C_HOVER)
            btn_label.configure(bg=C_HOVER)

    def _btn_leave(_e=None):
        if btn_label.cget("bg") != C_DISABLED:
            btn_frame.configure(bg=C_PRIMARY)
            btn_label.configure(bg=C_PRIMARY)

    btn_frame.bind("<Enter>", _btn_enter)
    btn_frame.bind("<Leave>", _btn_leave)
    btn_label.bind("<Enter>", _btn_enter)
    btn_label.bind("<Leave>", _btn_leave)

    def on_convert(_e=None):
        if not file_list:
            messagebox.showwarning("提示", "请先添加 NCM 文件")
            return

        btn_frame.configure(bg=C_DISABLED)
        btn_label.configure(bg=C_DISABLED, text="⏳  转换中...")
        btn_frame.unbind("<Enter>")
        btn_frame.unbind("<Leave>")

        progress_frame.pack(side=tk.RIGHT, padx=(0, 14))
        status_label.pack(side=tk.RIGHT, padx=(0, 6))
        status_label.configure(text="处理中...")
        bar.start()

        log("=" * 50)
        log(f"输出目录: {current_output}")
        log("开始转换...")

        def run():
            files = list(file_list)
            success, fail, errors = convert_files(files, current_output, callback=log)
            root.after(0, lambda: on_done(success, fail, errors))

        threading.Thread(target=run, daemon=True).start()

    btn_label.bind("<Button-1>", on_convert)

    def on_done(success: int, fail: int, errors: list[str]):
        bar.stop()
        progress_frame.pack_forget()
        status_label.pack_forget()

        btn_frame.configure(bg=C_PRIMARY)
        btn_label.configure(bg=C_PRIMARY, text="▶  开始转换")
        btn_frame.bind("<Enter>", _btn_enter)
        btn_frame.bind("<Leave>", _btn_leave)
        btn_label.bind("<Enter>", _btn_enter)
        btn_label.bind("<Leave>", _btn_leave)

        log(f"完成! 成功: {success}, 失败: {fail}")
        log(f"输出目录: {current_output}")
        log("=" * 50)

        if fail > 0:
            messagebox.showwarning(
                "转换完成 (有错误)",
                f"成功: {success} 首\n失败: {fail} 首\n\n失败原因:\n" + "\n".join(errors),
            )
        elif success > 0:
            messagebox.showinfo("转换完成", f"全部成功! 共 {success} 首\n\n文件保存在:\n{current_output}")
            # Don't auto-close — user may want to import more files
        else:
            messagebox.showwarning("提示", "没有检测到有效的 NCM 文件")

    # ── Drag-and-drop (tkinterdnd2 or fallback to ctypes) ──
    if _dnd_available:
        # Register drop targets for entire window, drop zone, and listbox
        drop_zone.drop_target_register("DND_Files")
        drop_zone.dnd_bind("<<Drop>>", lambda e: _add_paths(_parse_dnd_data(e.data)))
        listbox.drop_target_register("DND_Files")
        listbox.dnd_bind("<<Drop>>", lambda e: _add_paths(_parse_dnd_data(e.data)))
        # Also register the root for global drops
        root.drop_target_register("DND_Files")
        root.dnd_bind("<<Drop>>", lambda e: _add_paths(_parse_dnd_data(e.data)))
    else:
        _setup_ctypes_drop(root, listbox, file_list, log)

    root.mainloop()


def _parse_dnd_data(data: str) -> list[str]:
    """Parse file paths from tkinterdnd2 drop data.

    tkinterdnd2 returns paths wrapped in braces on Windows, e.g.:
    '{C:/Path/one.ncm} {C:/Path/two.ncm}'
    """
    import re
    paths = re.findall(r'\{([^}]+)\}', data)
    if not paths:
        # Fallback: split by space for paths without braces
        paths = data.split()
    return paths


def _setup_ctypes_drop(root, listbox, file_list, log):
    """Fallback: Windows file-drop via ctypes WndProc subclassing.

    This is less reliable than tkinterdnd2; used only when tkinterdnd2
    is not available (e.g., running from source without the package).
    """
    try:
        import ctypes
        from ctypes import wintypes

        GWL_EXSTYLE = -20
        WS_EX_ACCEPTFILES = 0x10
        WM_DROPFILES = 0x0233
        GWLP_WNDPROC = -4

        ctypes.windll.shell32.DragQueryFileW.argtypes = [
            wintypes.HANDLE, wintypes.UINT, ctypes.c_void_p, wintypes.UINT,
        ]
        ctypes.windll.shell32.DragQueryFileW.restype = wintypes.UINT
        ctypes.windll.shell32.DragFinish.argtypes = [wintypes.HANDLE]
        ctypes.windll.shell32.DragFinish.restype = None

        WNDPROC = ctypes.WINFUNCTYPE(
            ctypes.c_longlong,
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        )
        _old_proc = None
        _proc_ref = None

        def _wndproc(hwnd, msg, wp, lp):
            if msg == WM_DROPFILES:
                count = ctypes.windll.shell32.DragQueryFileW(wp, 0xFFFFFFFF, None, 0)
                new_files = []
                buf = ctypes.create_unicode_buffer(260)
                for i in range(count):
                    ctypes.windll.shell32.DragQueryFileW(wp, i, buf, 260)
                    new_files.append(buf.value)
                ctypes.windll.shell32.DragFinish(wp)
                root.after(0, lambda fs=new_files: _add_drop(fs))
                return 0
            return ctypes.windll.user32.CallWindowProcW(_old_proc, hwnd, msg, wp, lp)

        def _add_drop(paths):
            for p in paths:
                fpath = Path(p)
                if fpath.suffix.lower() == ".ncm" and p not in file_list:
                    file_list.append(p)
                    listbox.insert(tk.END, fpath.name)
                    log(f"已添加: {fpath.name}")

        def _setup():
            nonlocal _old_proc, _proc_ref
            hwnd = wintypes.HWND(root.winfo_id())
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style | WS_EX_ACCEPTFILES)
            _proc_ref = WNDPROC(_wndproc)
            _old_proc = ctypes.windll.user32.SetWindowLongPtrW(
                hwnd, GWLP_WNDPROC, ctypes.cast(_proc_ref, ctypes.c_void_p).value
            )

        root.after(200, _setup)
    except Exception:
        pass


# ── Silent mode (files dragged onto EXE icon) ──────────────────────────

def _silent_error(errors: list[str]):
    """Show error messagebox and exit."""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    messagebox.showerror(
        "NCM转换失败",
        "转换过程中出现问题:\n\n" + "\n".join(errors),
    )
    root.destroy()


def run_silent(files: list[str]):
    """Silent mode: no console, no window — only pop up on errors."""
    import tkinter as tk
    from tkinter import messagebox

    # Only keep .ncm files
    ncm_files = [f for f in files if Path(f.strip().strip('"')).suffix.lower() == ".ncm"]
    if not ncm_files:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        messagebox.showwarning(
            "NCM转换工具",
            "没有检测到NCM文件。\n\n请将 .ncm 格式的音乐文件拖到程序图标上。",
        )
        root.destroy()
        return

    # Load / prompt for output folder
    cfg = load_config()
    if not cfg["output_dir"]:
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        result = messagebox.askokcancel(
            "初次使用 — 选择输出目录",
            "请选择音乐文件的保存位置。\n\n"
            "之后拖NCM文件到图标就会自动转换到这个目录，\n"
            "无需再次设置。打开程序可以随时更改。",
        )
        if not result:
            root.destroy()
            return
        path = filedialog.askdirectory(title="选择音乐输出文件夹")
        root.destroy()
        if not path:
            return
        save_config(path)
        output_dir = Path(path)
    else:
        output_dir = Path(cfg["output_dir"])
        if not output_dir.exists():
            try:
                output_dir.mkdir(parents=True)
            except Exception:
                _silent_error([f"输出文件夹不存在且无法创建:\n{output_dir}"])
                return

    _, _, errors = convert_files(ncm_files, output_dir)
    if errors:
        _silent_error(errors)
    # On success: exit silently, files are in output_dir


# ── Entry point ────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        run_silent(sys.argv[1:])
    else:
        run_gui()


if __name__ == "__main__":
    main()
