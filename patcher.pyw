import os
import struct
import subprocess
import sys
import threading
import zlib

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

A_OLD = b'if(k?.hasValidAuth){if(g!=="signedIn"){'
A_NEW = b'if(k?.hasValidAuth||k?.ineligible){if(g!=="signedIn"){'
B_OLD = b'c?.case==="ineligible"?a._authActor.send({type:"SET_INELIGIBLE",message:b,verificationUrl:c.value.verificationUrl||\nvoid 0}):'
B_NEW = b'c?.case==="ineligible"?a._authActor.send({type:"AUTH_SUCCESS",tokenInfo:{accessToken:""},scopes:[],project:"aicode-consumers"}):'

EXE_NAME = "resources\\bin\\language_server.exe"
APP_EXE = "Antigravity.exe"


def find_zips(buf):
    zips, pos = [], 0
    while True:
        i = buf.find(b"PK\x05\x06", pos)
        if i < 0:
            return zips
        pos = i + 4
        n, cdsize, cdoff = struct.unpack_from("<HII", buf, i + 10)
        if not (n and cdsize and cdoff):
            continue
        base = i - cdsize - cdoff
        if base <= 0 or buf[base + cdoff:base + cdoff + 4] != b"PK\x01\x02":
            continue
        zips.append((base, n, cdoff))


def cd_entries(buf, n, cdoff, base):
    out, p = {}, base + cdoff
    for _ in range(n):
        if buf[p:p + 4] != b"PK\x01\x02":
            break
        nlen, elen, clen = struct.unpack_from("<HHH", buf, p + 28)
        name = buf[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        out.setdefault(name, p)
        p += 46 + nlen + elen + clen
    return out


def cd_fields(buf, p):
    crc, csize, usize = struct.unpack_from("<III", buf, p + 16)
    nlen, elen = struct.unpack_from("<HH", buf, p + 28)
    lho, = struct.unpack_from("<I", buf, p + 42)
    return crc, csize, usize, lho, nlen, elen


def locate(buf):
    for base, n, cdoff in find_zips(buf):
        entries = cd_entries(buf, n, cdoff, base)
        if "main.js" in entries:
            p = entries["main.js"]
            crc, csize, usize, lho, nlen, elen = cd_fields(buf, p)
            loff = base + lho
            return {
                "entry": p,
                "data": loff + 30 + nlen + elen,
                "crc": crc,
                "csize": csize,
                "usize": usize,
                "lho": loff,
            }
    return None


def read_js(buf, info):
    raw = zlib.decompressobj(-15).decompress(buf[info["data"]:info["data"] + info["csize"]])
    if len(raw) != info["usize"] or zlib.crc32(raw) != info["crc"]:
        raise ValueError("исходный main.js не прошёл проверку CRC — сборка нестандартная")
    return raw


def detect_install():
    home = os.environ.get("LOCALAPPDATA", "")
    dirs = [
        os.path.join(home, "Programs", "Antigravity"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Antigravity"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Antigravity"),
    ]
    try:
        out = subprocess.run(
            ["wmic", "process", "where", "name='Antigravity.exe'", "get", "ExecutablePath", "/value"],
            capture_output=True, text=True, timeout=20,
        ).stdout
        for line in out.splitlines():
            if line.startswith("ExecutablePath=") and line[15:].strip():
                dirs.insert(0, os.path.dirname(line[15:].strip()))
    except Exception:
        pass
    for d in dirs:
        exe = os.path.join(d, EXE_NAME)
        if os.path.isfile(exe):
            return d, exe
    return None, None


def app_running():
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Antigravity.exe", "/NH"],
                             capture_output=True, text=True, timeout=20).stdout
        return "Antigravity.exe" in out
    except Exception:
        return False


def kill_app():
    for name in ("Antigravity.exe", "language_server.exe"):
        subprocess.run(["taskkill", "/F", "/T", "/IM", name],
                       capture_output=True, text=True, timeout=30)


def state_of(exe):
    if not exe or not os.path.isfile(exe):
        return "missing", "language_server.exe не найден"
    size = os.path.getsize(exe)
    buf = open(exe, "rb").read()
    info = locate(buf)
    if not info:
        return "unknown", "во встроенном архиве нет main.js"
    try:
        js = read_js(buf, info)
    except ValueError as e:
        return "unknown", str(e)
    if A_NEW in js and B_NEW in js:
        return "patched", "патч применён (%d МБ, main.js %d КБ)" % (size >> 20, len(js) >> 10)
    if A_OLD in js and B_OLD in js:
        return "clean", "патч не применён (%d МБ)" % (size >> 20)
    return "unknown", "якоря не найдены — другая версия Antigravity"


def apply_patch(exe, log):
    backup = exe + ".orig"
    if app_running():
        log("закрываю Antigravity…")
        kill_app()
    buf = bytearray(open(exe, "rb").read())
    info = locate(buf)
    if not info:
        raise RuntimeError("во встроенном архиве нет main.js")
    js = read_js(buf, info)
    patched = js.replace(A_OLD, A_NEW) if A_OLD in js else js
    if B_OLD in patched:
        patched = patched.replace(B_OLD, B_NEW)
    if patched == js:
        raise RuntimeError("якоря не найдены — эта сборка не поддерживается")

    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    blob = comp.compress(patched) + comp.flush()
    if len(blob) > info["csize"]:
        raise RuntimeError("патч не влезает: %d > %d байт" % (len(blob), info["csize"]))

    if not os.path.exists(backup):
        log("сохраняю копию: " + backup)
        with open(backup, "wb") as f:
            f.write(buf)

    size_before = len(buf)
    off = info["data"]
    buf[off:off + info["csize"]] = blob + b"\x00" * (info["csize"] - len(blob))
    crc = zlib.crc32(patched) & 0xFFFFFFFF
    struct.pack_into("<III", buf, info["lho"] + 14, crc, len(blob), len(patched))
    struct.pack_into("<III", buf, info["entry"] + 16, crc, len(blob), len(patched))

    with open(exe, "r+b") as f:
        f.write(buf)

    check = open(exe, "rb").read()
    if len(check) != size_before:
        raise RuntimeError("размер файла изменился (%d -> %d)" % (size_before, len(check)))
    again = locate(check)
    js2 = read_js(check, again)
    if js2 != patched:
        raise RuntimeError("проверка после записи не сошлась")
    log("готово: поставил %d байт, main.js %d -> %d" % (len(blob), len(js), len(patched)))


def restore(exe, log):
    backup = exe + ".orig"
    if not os.path.exists(backup):
        raise RuntimeError("нет резервной копии " + backup)
    if app_running():
        log("закрываю Antigravity…")
        kill_app()
    subprocess.run(["attrib", "-r", exe], capture_output=True, timeout=20)
    with open(exe, "wb") as dst, open(backup, "rb") as src:
        dst.write(src.read())
    log("вернул оригинал: %d байт" % os.path.getsize(exe))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Antigravity Patcher")
        self.geometry("720x430")
        self.minsize(640, 380)
        self.configure(bg="#111214")
        self.exe = None
        self.root_dir = None

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", padding=(12, 6), font=("Segoe UI", 10))
        style.configure("TFrame", background="#111214")
        style.configure("TLabel", background="#111214", foreground="#d7dae0", font=("Segoe UI", 10))

        head = tk.Label(self, text="Antigravity", bg="#111214", fg="#f2f4f8",
                        font=("Segoe UI Semibold", 17), anchor="w")
        head.pack(fill="x", padx=18, pady=(16, 0))
        self.path_lbl = tk.Label(self, text="ищу установку…", bg="#111214", fg="#7d828c",
                                 font=("Segoe UI", 9), anchor="w", justify="left", wraplength=680)
        self.path_lbl.pack(fill="x", padx=18, pady=(2, 10))
        self.state_lbl = tk.Label(self, text="", bg="#111214", fg="#e9c46a",
                                  font=("Segoe UI Semibold", 12), anchor="w")
        self.state_lbl.pack(fill="x", padx=18)

        row = ttk.Frame(self)
        row.pack(fill="x", padx=18, pady=12)
        self.btn_state = ttk.Button(row, text="Обновить", command=self.refresh)
        self.btn_patch = ttk.Button(row, text="Пропатчить", command=self.do_patch)
        self.btn_restore = ttk.Button(row, text="Откатить", command=self.do_restore)
        self.btn_launch = ttk.Button(row, text="Запустить Antigravity", command=self.do_launch)
        for b in (self.btn_state, self.btn_patch, self.btn_restore, self.btn_launch):
            b.pack(side="left", padx=(0, 8))

        self.log_box = scrolledtext.ScrolledText(self, height=10, bg="#0b0c0e", fg="#a9b2c0",
                                                 insertbackground="#a9b2c0", relief="flat",
                                                 font=("Consolas", 9), padx=10, pady=8)
        self.log_box.pack(fill="both", expand=True, padx=18, pady=(0, 16))

        self.refresh()

    def log(self, text):
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")

    def refresh(self):
        self.root_dir, self.exe = detect_install()
        if not self.exe:
            self.path_lbl.configure(text="Antigravity не найден — установи его или укажи папку вручную")
            self.state_lbl.configure(text="не найден", fg="#e76f51")
            return
        self.path_lbl.configure(text=self.exe)
        kind, text = state_of(self.exe)
        colors = {"patched": "#2a9d8f", "clean": "#e9c46a", "unknown": "#e76f51", "missing": "#e76f51"}
        self.state_lbl.configure(text=text, fg=colors.get(kind, "#d7dae0"))
        self.btn_patch.state(["disabled"] if kind == "patched" else ["!disabled"])
        self.btn_restore.state(["!disabled"] if os.path.exists(self.exe + ".orig") else ["disabled"])

    def busy(self, fn):
        for b in (self.btn_state, self.btn_patch, self.btn_restore, self.btn_launch):
            b.state(["disabled"])

        def run():
            try:
                fn()
            except Exception as e:
                self.log("ошибка: %s" % e)
            finally:
                self.after(0, self.refresh)

        threading.Thread(target=run, daemon=True).start()

    def do_patch(self):
        if not self.exe:
            return
        if not messagebox.askyesno("Antigravity Patcher",
                                   "Применить патч к language_server.exe?\n\n"
                                   "Antigravity будет закрыт. Резервная копия: language_server.exe.orig"):
            return
        self.busy(lambda: apply_patch(self.exe, self.log))

    def do_restore(self):
        if not self.exe:
            return
        if not messagebox.askyesno("Antigravity Patcher", "Вернуть оригинальный language_server.exe?"):
            return
        self.busy(lambda: restore(self.exe, self.log))

    def do_launch(self):
        if not self.exe:
            return
        target = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(self.exe))), APP_EXE)
        try:
            os.startfile(target)
            self.log("запускаю " + target)
        except OSError as e:
            self.log("не удалось запустить: %s" % e)


if __name__ == "__main__":
    if "--check" in sys.argv:
        root, exe = detect_install()
        print("install:", root)
        print("exe:", exe)
        if exe:
            print("state:", state_of(exe))
        sys.exit(0)
    App().mainloop()
