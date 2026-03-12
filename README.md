# Port_Scanner 3.0

一个功能完整的端口扫描器，支持TCP全连接扫描和SYN半开放扫描，集成服务识别与Banner抓取功能。

---

## 📖 项目简介

本项目是一个教育性质的端口扫描工具，旨在帮助网络安全学习者理解：

- TCP/IP协议栈与端口扫描原理
- 多线程并发编程实践
- Scapy库在网络安全中的应用
- 服务识别与Banner抓取技术
- 不同扫描方式的优缺点对比

**⚠️ 法律声明：本工具仅用于授权测试和教育目的，未经授权扫描他人系统可能违反法律法规！**

---

## ✨ 功能特性

### 🔍 双模式扫描
| 扫描模式 | 原理 | 优点 | 缺点 |
|:---|:---|:---|:---|
| **TCP全连接扫描** | 完整的三次握手 | 准确可靠，无需特殊权限 | 容易被日志记录，速度较慢 |
| **SYN半开放扫描** | 只发SYN，收SYN-ACK后发RST | 速度快，不易被发现 | 需要root/管理员权限 |

### 🎯 核心功能
- ✅ **多线程并发** - 大幅提升扫描速度
- ✅ **批量端口扫描** - 支持单端口、端口列表、端口范围
- ✅ **服务识别** - 根据端口号识别常见服务
- ✅ **Banner抓取** - 获取服务版本信息
- ✅ **智能探针** - 针对不同协议发送特定探测包
- ✅ **HTTP虚拟主机支持** - 可指定Host头获取正确Banner
- ✅ **结果保存** - 自动保存扫描结果到文件
- ✅ **跨平台支持** - Windows/Linux/macOS

### 🛡️ 服务识别能力
| 端口 | 服务 | 支持Banner |
|:---|:---|:---|
| 21 | FTP | ✅ 版本、欢迎信息 |
| 22 | SSH | ✅ 版本、协议 |
| 23 | Telnet | ⚠️ 基础识别 |
| 25 | SMTP | ✅ 服务器标识 |
| 53 | DNS | ⚠️ 基础识别 |
| 80 | HTTP | ✅ Server头、版本 |
| 110 | POP3 | ✅ 欢迎信息 |
| 143 | IMAP | ✅ 欢迎信息 |
| 443 | HTTPS | ✅ Server头、版本 |
| 3306 | MySQL | ✅ 版本信息 |
| 3389 | RDP | ⚠️ 基础识别 |
| 8080 | HTTP-Alt | ✅ Server头、版本 |

---

## 🚀 快速开始

### 环境要求

- Python 3.6+
- 依赖库：scapy（可选，用于SYN扫描）

### 安装

```bash
# 克隆仓库
git clone https://github.com/moon-struck630/port-scanner.git
cd port-scanner

# 安装依赖（推荐使用虚拟环境）
pip install scapy

# 如果只需要TCP扫描，可以不安装scapy
```

## 基础使用
```bash
# 运行脚本
python port_scanner.py

# 交互式菜单
============================================================
端口扫描系统3.0
============================================================

请选择模式
1. TCP全连接扫描
2. SYN半开放扫描
3. 退出
输入选项(1-3): 
```

### 示例1：TCP扫描常见端口
```text
输入选项(1-3): 1
请输入目标IP或域名：192.168.1.1
请输入端口范围(如80,443或1-1000): 21,22,23,25,80,443,3306,3389,8080
请输入域名（用于HTTP请求，直接回车跳过）：router.local

开始TCP扫描192.168.1.1的9个端口
============================================================

[+]端口22开放 - SSH-2.0-OpenSSH_7.4
[+]端口80开放 - HTTP - nginx/1.16.1
[+]端口443开放 - HTTPS - Apache/2.4.41 (Ubuntu)
[+]端口8080开放 - HTTP-Alt - Apache Tomcat/8.5.50

============================================================
扫描完成统计
============================================================
总扫描时间：3.25秒
开放端口：4

开放端口详情：
端口 22: SSH
    Banner: SSH-2.0-OpenSSH_7.4
端口 80: HTTP
    Banner: HTTP/1.1 200 OK - Server: nginx/1.16.1
端口 443: HTTPS
    Banner: HTTP/1.1 200 OK - Server: Apache/2.4.41 (Ubuntu)
端口 8080: HTTP-Alt
    Banner: HTTP/1.1 200 OK - Server: Apache-Coyote/1.1

是否保存结果？(y/n): y
结果已保存到scan_192.168.1.1_20240312_143025.txt
```

### 示例2：SYN扫描（需要root权限）
```bash
# Linux/macOS
sudo python port_scanner.py

# Windows（以管理员身份运行）
python port_scanner.py

输入选项(1-3): 2
请输入目标IP或域名：scanme.nmap.org
请输入端口范围(如80,443或1-1000): 1-1000
请输入域名（用于HTTP请求，直接回车跳过）：

使用SYN半开放扫描...
[+]端口22开放 - SSH - SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+]端口80开放 - HTTP - Apache/2.4.7 (Ubuntu)
[+]端口443开放 - HTTPS - Apache/2.4.7 (Ubuntu)
[-]端口21被过滤
[-]端口23关闭
...
```

## 核心原理详解
### 1. TCP全连接扫描
```python
def tcp_connect_scanner(self, target, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    return result == 0, "open" if result == 0 else "closed"
```
#### 通信过程：

```text
客户端                 服务器
   |       SYN        |
   |----------------->|
   |     SYN-ACK      |
   |<-----------------|
   |       ACK        |
   |----------------->|
   |       RST        |
   |----------------->|  （关闭连接）
```
### 2. SYN半开放扫描
```python
def syn_scanner(self, ip, port, timeout=2):
    # 构建SYN包
    pkt = IP(dst=ip) / TCP(dport=port, flags='S')
    # 等待响应
    response = sr1(pkt, timeout=timeout, verbose=0)
    
    if response and response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            # 发送RST关闭连接
            rst_pkt = IP(dst=ip) / TCP(dport=port, flags='R')
            sr1(rst_pkt, timeout=timeout, verbose=0)
            return True, "open"
        elif flags == 0x14:  # RST-ACK
            return False, "closed"
```
#### 通信过程：

```text
客户端                 服务器
   |       SYN        |
   |----------------->|
   |     SYN-ACK      |
   |<-----------------|
   |       RST        |  （不发送ACK）
   |----------------->|
```
### 3. Banner抓取原理
- 对不同协议发送特定的"探针"：

|协议	|探针	|期望响应|
|:---|:---|:---|
|HTTP	|HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n	|Server: Apache/2.4.41|
|FTP	|HELP\r\n	220 |FTP server ready|
|SMTP	|EHLO example.com\r\n	|250-smtp.example.com|
|SSH	|\r\n	|SSH-2.0-OpenSSH_7.4|

## 项目结构
```text
port-scanner/
│
├── port_scanner.py          # 主程序
├── README.md                 # 本文档
├── requirements.txt          # 依赖列表 
├── scan_8_8_8_8_20260305_163256.txt
└── scan_140_82_112_3_20260305_163701.txt  #扫描文件（自动创建）
```

## 类与方法参考
### ServiceDetector 类
|方法	|说明|
|:---|:---|
|tcp_connect_scanner(target, port, timeout)	|TCP全连接扫描|
|syn_scanner(ip, port, timeout)	|SYN半开放扫描|
|get_banner(target, port, timeout, hostname)	|获取服务Banner|
|analyze_banner(port, banner, hostname)	|分析Banner提取版本|
|get_service_name(port)	|根据端口获取服务名|

### PortScanner 类
|方法	|说明|
|:---|:---|
|__init__(target, timeout, max_threads)	|初始化扫描器|
|scan_port(port, hostname)	|扫描单个端口|
|scan_ports(port_range, hostname)	|批量扫描端口|
|save_result(filename)	|保存扫描结果|

## ⚙️ 高级配置
### 调整扫描参数
```python
# 创建扫描器时自定义参数
scanner = PortScanner(
    target="192.168.1.1",
    timeout=3,        # 连接超时（秒）
    max_threads=200   # 最大并发线程数
)
```
### 自定义探针
- 在 ServiceDetector.__init__ 中修改 self.probes 字典：

```python
self.probes = {
    21: b"HELP\r\n",                    # FTP
    22: b"\r\n",                         # SSH
    25: b"EHLO example.com\r\n",         # SMTP
    80: b"HEAD / HTTP/1.0\r\n\r\n",      # HTTP
    110: b"USER test\r\n",                # POP3
    143: b"1 LOGIN test test\r\n",        # IMAP
    443: b"",                              # HTTPS
    3306: b"",                             # MySQL
    8080: b"HEAD / HTTP/1.0\r\n\r\n"       # HTTP-Alt
}
```

## 常见问题
### Q1: SYN扫描报错 "Scapy库不可用"
#### 解决方法：
```bash
pip install scapy
# Linux可能需要安装libpcap
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel     # CentOS/RHEL
```
### Q2: SYN扫描在Windows上报错 "操作必须使用一个提升的权限"
#### 解决方法：以管理员身份运行

- 右键点击命令提示符 → "以管理员身份运行"

- 或使用 runas 命令

### Q3: 扫描速度太慢
#### 优化方案：

- 减小 timeout 值（但可能漏掉慢速响应）

- 增加 max_threads 值（但可能被目标防火墙拦截）

- 使用SYN扫描代替TCP扫描

```python
scanner = PortScanner(target, timeout=1, max_threads=500)
```
### Q4: 扫描结果全是 "filtered"
#### 可能原因：

1. 目标启用了防火墙

2. 网络连接问题

3. 超时时间太短

4. 目标确实没有开放端口

### 解决方法：

- 尝试增加 timeout

- 用 ping 测试连通性

- 换TCP扫描试试

### Q5: HTTP Banner显示不全或乱码
#### 解决方法：提供正确的Host头

```text
请输入域名（用于HTTP请求，直接回车跳过）：www.example.com
```
