```

..######.....###....########.##........#######...######..
.##....##...##.##......##....##.......##.....##.##....##.
.##........##...##.....##....##.......##.....##.##.......
.##.......##.....##....##....##.......##.....##.##...####
.##.......#########....##....##.......##.....##.##....##.
.##....##.##.....##....##....##.......##.....##.##....##.
..######..##.....##....##....########..#######...######..

```
# catlog

Multi-platform log analyzer for security incidents

---

## 🧠 Wishlist

This project is under active development. Here’s what I plan to include:

- [ ] **Linux Log Support**
  - Parse `/var/log/auth.log`, `/var/log/secure`, and `/var/log/syslog`
  - Detect failed/successful logins, sudo events, and SSH access from new IPs

- [ ] **Windows Event Log Parsing**
  - Detect common security events (e.g., Event IDs 4624, 4625, 4672)
  - Use `pywin32` or WMI to pull events directly

- [ ] **Web Server Log Analysis**
  - Apache and Nginx log parsing
  - Detect common attack patterns (SQL injection, path traversal, bots)

- [ ] **Modular Design**
  - Individual parser modules for each log type
  - Unified CLI interface

- [ ] **Alerting & Reporting**
  - Print to terminal
  - Export to JSON/CSV
  - (Future) Discord webhooks or email notifications

- [ ] **Threat Intelligence Integration**
  - GeoIP lookup for IP addresses
  - Check IPs against AbuseIPDB

- [ ] **Tuning & Whitelisting**
  - Allow user-defined rules for known/allowed events

---

## 🛠 Installation (Coming Soon)

```bash
git clone https://github.com/yourusername/catlog.git
cd catlog
pip install -r requirements.txt
```
---

## Planned Usage
```
python main.py
```

---

## 📁 Planned Structure
```
catlog/
├── core/
│   └── utils.py
├── parsers/
│   ├── linux.py
│   ├── windows.py
│   └── web.py
├── main.py
└── README.md
```

---

📌 Roadmap
- [ ] Build basic CLI structure

- [ ] Add Linux log parser

- [ ] Add Windows log parser

- [ ] Add web server log parser

- [ ] Create alerting/reporting system

---

🐾 License
MIT License. Use freely and contribute!

---

❤️ Credits
ASCII art found and adapted from community ASCII resources.



