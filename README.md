# 🚨 SlackSecAlert — Burp Suite to Slack Alerts for Production Domains

`SlackSecAlert` is a lightweight Burp Suite extension written in Jython that monitors HTTP traffic and sends rich Slack notifications whenever a production domain is accessed — whether through browsing or active scans.

This is perfect for security engineers and red teams who want visibility, accountability, and audit trails during security testing on sensitive environments.

---

## ✨ Features

- 🔐 Detects access to production domains (defined in `production_domains.txt`)
- 💬 Sends rich Slack alerts with emoji, timestamp, and responsible tester tag
- 🛠️ Works with **Proxy**, **Scanner**, and **Intruder** tools in Burp
- ⏲️ Configurable cooldown to prevent alert fatigue
- ✅ Simple UI inside Burp Suite to manage settings

---

## 📦 Installation

### 🐍 Prerequisites

- **Burp Suite (Professional or Community)**
- **Jython Standalone JAR** (recommended version: `jython-standalone-2.7.2.jar`)

Download from: https://www.jython.org/download

---

### 🔌 Step-by-Step Setup

1. **📁 Clone or download this repository**  
   Save the extension file `SlackSecAlert.py` somewhere on your system.

2. **📄 Create your `production_domains.txt` file**  
   This file should be in the same folder as your script.

   Example content:
myapp.com api.myapp.com production.example.org


3. **📦 Load the extension in Burp Suite**
- Go to `Extender` > `Extensions` > `Add`
- Extension Type: `Python`
- Select the `.py` file
- Set the Jython JAR path under `Options > Python Environment`

4. **⚙️ Configure from the Burp Tab**
- Open the `Slack Sec Alert` tab
- Paste your **Slack Incoming Webhook URL**
- Enter your **Slack Username** (the person doing testing)
- Set the **cooldown** in minutes (default is 5)
- ✅ Toggle:
  - "Alert on Browse" to catch Proxy usage
  - "Alert on Active Scan" to catch Scanner/Intruder activity

5. **💥 Test**
- Browse to a domain in your list
- You should see a Slack message like:
### 🔍 Burp Suite Activity Detected on Production

**Environment:** Production  
**Domain:** `myapp.com`  
**URL:** [https://myapp.com/secret](https://myapp.com/secret)  
**Time:** `2025-04-30T15:00:00Z`

ℹ️ _This activity is part of security testing. Contact **@yourname** if unsure._



## 🧑‍💻 Maintainer

**You!** Feel free to fork, enhance, and share.  
Add features like:
- Logging alerts to file
- Support for more Burp tools
- Sound or pop-up alerting

### 🚀 Happy Testing! Stay visible, stay accountable.  
