# proxy-washer
a tool to wash clash nodes
# 🧼 proxy-washer (赛博节点清洗器)

> **“授人以鱼不如授人以渔。清洗脚本都给了，造出一堆节点不轻轻松松吗？”**
> 
> 一个专为极客打造的轻量级 Clash 节点清洗与分发系统。无需上传任何敏感的节点数据，只提供最纯粹的清洗引擎。

## 📖 项目简介

`proxy-washer` 采用 **“云端伪装分发 + 本地极速清洗”** 的分离架构。它不会在 GitHub 上存放任何节点数据，而是提供了一套完整的工具链：你可以用它去抓取公开订阅，在本地或云端进行极速并发测速、协议过滤，并生成干净整洁的 Clash 订阅文件。

### ✨ 核心特性

*   **☁️ 云端面板 (`app.py`)**：
    *   **FastAPI 异步架构**：极低性能占用，完美适配 KataBump、Pterodactyl 等轻量级容器。
    *   **赛博结界（UUID 防护）**：面板路径完全隐藏在随机的 UUID 之下，拒绝字典爆破。
    *   **物理级伪装**：根目录反向代理至无关网页（如公交站牌），完美欺骗主动探测扫描器。
    *   **自动分流转发**：支持主订阅与本地专属订阅双通道，互不干扰。
*   **💻 本地清洗 (`local-test.py`)**：
    *   **千级并发测速**：基于 `aiohttp` 和 `asyncio`，百兆并发轻松拿捏。
    *   **IPv6 智能放行**：自动检测本地环境，无 IPv6 时对相关节点直接免测放行，防止误杀 Cloudflare WARP 等优质节点。
    *   **SFTP 自动回传**：清洗完毕后，一键无缝上传至云端服务器。
    *   **深度净化**：剔除无效节点，清理恶意字符，强制按协议（SS、VLESS、Trojan 等）生成自动测速分组。

## 🛠️ 快速开始

### 1. 环境依赖

请确保安装了 Python 3.8+，然后安装依赖：

```bash
pip install -r requirements.txt
```

(注：本地脚本运行需额外安装 paramiko 用于 SFTP 上传)

2. 云端部署 (app.py)

将 app.py 放在你的容器目录中。强烈建议通过环境变量设置你的专属 UUID：

```bash
export PANEL_UUID="your_super_secret_uuid_here"
python app.py
```

启动后，你的面板地址将是：
http://你的IP或域名:20270/panel/your_super_secret_uuid_here

3. 本地清洗 (local-test.py)

在手机 (Termux/Pydroid 3) 或电脑上运行：

```bash
python local-test.py
```

根据交互提示，你可以选择：

1. 输入订阅链接或本地文件。
2. 脚本会自动拉取、测速、去重、分组。
3. 提示上传时，输入你的 SFTP 信息，清洗好的文件将自动飞入云端。

📂 架构与数据安全

本项目遵循 计算与状态分离 的原则：

```text
.
├── app.py               # 云端 Web 面板核心逻辑
├── local-test.py        # 本地并发测速与清洗引擎
├── requirements.txt     # 环境依赖
├── LICENSE              # MIT 协议
└── data/                # (本地或云端生成，已被 .gitignore 忽略)
    ├── subscription.yaml    # 云端自动清洗的节点池
    └── cloud_cleaned.yaml   # 本地清洗后上传的专属节点池
```

⚠️ 注意：请绝对不要将 data 文件夹及其下的 .yaml 文件提交到 Git 仓库！ 节点数据具有时效性和隐私性，请妥善保存在你自己的服务器或个人设备上。

🔒 免责声明 (Disclaimer)

1. 本工具仅供 Python 编程学习、网络协议分析及自动化测试 使用。
2. 请勿将本工具用于任何违反当地法律法规的用途。
3. 使用本工具抓取的公开节点，其安全性与可用性由节点提供者决定，本项目不对其纯净度及安全性负责。请勿在使用公共节点时进行任何涉及个人隐私与财产安全的高危操作（如网银交易）。

---

Made with ❤️ by siciyuan. 愿你的节点永远 48ms，永远不超时。
