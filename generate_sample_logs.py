import os
import random
from datetime import datetime, timedelta

random.seed(7)
os.makedirs("sample_logs", exist_ok=True)
base = datetime(2026, 9, 28, 2, 0, 0)


def sys_ts(t):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def ssh(t, msg):
    return f"{sys_ts(t)} web01 sshd[{random.randint(1000, 9999)}]: {msg}"


auth = []
for i in range(20):
    t = base + timedelta(minutes=i * 37)
    auth.append(ssh(t, f"Accepted publickey for alice from 10.0.0.{random.randint(2, 20)} port {random.randint(30000, 60000)} ssh2"))
t = base + timedelta(hours=1)
for i in range(60):
    auth.append(ssh(t + timedelta(seconds=i * 4), f"Failed password for root from 203.0.113.50 port {40000 + i} ssh2"))
for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "git", "deploy"]):
    auth.append(ssh(t + timedelta(minutes=30, seconds=i * 20), f"Invalid user {u} from 198.51.100.23 port {50000 + i}"))
    auth.append(ssh(t + timedelta(minutes=30, seconds=i * 20 + 1), f"Failed password for invalid user {u} from 198.51.100.23 port {50000 + i} ssh2"))
t2 = base + timedelta(hours=3)
for i in range(8):
    auth.append(ssh(t2 + timedelta(seconds=i * 10), f"Failed password for bob from 192.0.2.77 port {41000 + i} ssh2"))
auth.append(ssh(t2 + timedelta(seconds=95), "Accepted password for bob from 192.0.2.77 port 41010 ssh2"))
auth.sort(key=lambda l: datetime.strptime(f"2026 {l[:15]}", "%Y %b %d %H:%M:%S"))
open("sample_logs/auth.log", "w").write("\n".join(auth) + "\n")


def web(t, ip, path, status, ua="Mozilla/5.0", method="GET"):
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {random.randint(200, 5000)} "-" "{ua}"'


acc = []
for i in range(200):
    acc.append(web(base + timedelta(seconds=i * 40), f"10.0.1.{random.randint(2, 30)}",
                   random.choice(["/", "/index.html", "/about", "/css/site.css"]), 200))
t = base + timedelta(hours=2)
for i, pth in enumerate(["/admin", "/.env", "/.git/config", "/wp-login.php", "/backup.zip", "/phpmyadmin/"] * 4):
    acc.append(web(t + timedelta(seconds=i), "203.0.113.9", pth, 404, "Nikto/2.5.0"))
acc.append(web(t, "198.51.100.77", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users", 200))
acc.append(web(t, "198.51.100.77", "/products?id=1'%20OR%20'1'='1", 500))
acc.append(web(t, "198.51.100.77", "/download?file=../../../../etc/passwd", 200))
acc.append(web(t, "198.51.100.77", "/search?q=<script>alert(1)</script>", 200))
acc.append(web(t, "198.51.100.77", "/ping?host=8.8.8.8;cat%20/etc/passwd", 403))
for i in range(150):
    acc.append(web(t + timedelta(minutes=5, milliseconds=i * 300), "192.0.2.200", "/", 200, "python-requests/2.31"))
acc.sort(key=lambda l: datetime.strptime(l.split("[")[1].split()[0], "%d/%b/%Y:%H:%M:%S"))
open("sample_logs/access.log", "w").write("\n".join(acc) + "\n")
print("Wrote sample_logs/auth.log and sample_logs/access.log")
