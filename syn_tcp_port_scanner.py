import socket
import threading
import time
import re
import sys
from queue import Queue
from datetime import datetime

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0  # 关闭scapy的冗长输出
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy库不可用，TCP SYN扫描将无法使用！")
    print("请运行pip install scapy安装scapy库")

class ServiceDetector: 
    def __init__(self):
        self.probes = {
            21: b"HELP\r\n",
            22: b"\r\n",
            25: b"EHLO example.com\r\n",
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            110: b"USER test\r\n",
            143: b"1 LOGIN test test\r\n",
            443: b"",  # HTTPS通常不发送banner，但我们可以尝试建立SSL连接来获取一些信息
            3306: b"",
            8080: b"HEAD / HTTP/1.0\r\n\r\n"
        }

    # TCP全连接扫描
    def tcp_connect_scanner(self, target, port, timeout=2):  # 增加默认超时
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return True, "open"
            else:
                return False, "closed"
        except Exception as e:
            return False, f"error: {e}"

    # SYN半开放扫描器
    def syn_scanner(self, ip, port, timeout=2):  # 增加默认超时
        if not SCAPY_AVAILABLE:
            return False, "Scapy库不可用"
        try:
            # 构建SYN数据包
            pkt = IP(dst=ip) / TCP(dport=port, flags='S')
            # 发送数据包并等待响应
            response = sr1(pkt, timeout=timeout, verbose=0)
            if response is None:
                return False, "filtered"
            # 检查响应
            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # 发送RST包关闭连接
                    rst_pkt = IP(dst=ip) / TCP(dport=port, flags='R')
                    sr1(rst_pkt, timeout=timeout, verbose=0)
                    return True, "open"
                elif tcp_layer.flags == 0x14:  # RST-ACK
                    return False, "closed"
            return False, "Unknown"
        except Exception as e:
            return False, f"error: {e}"

    def get_banner(self, target, port, timeout=3, hostname=None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            if port in [80, 443, 8080]:  # 这三个常见端口为HTTP/HTTPS服务，发送HTTP请求获取banner
                host = hostname if hostname else target
                http_request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
                sock.send(http_request.encode())
            elif port in self.probes and self.probes[port]:  # 检查是否在预设的探针字典内，并且探针不为空
                probe = self.probes[port]
                # 如果是web端口且有hostname，替换Host头
                if port in [80, 8080] and hostname:
                    probe = probe.replace(b"Host:", f"Host: {hostname}".encode())  # encode()将字符串转换为字节串
                sock.send(probe)
            banner = sock.recv(4096)  # 接收最多4096字节的响应
            sock.close()
            # 尝试解码banner为字符串，如果失败则保留原始字节串
            try:
                banner = banner.decode(errors='ignore').strip()
            except:
                banner = str(banner)
            return self.analyze_banner(port, banner, hostname)
        except Exception as e:  # 如果错误，返回错误信息
            return {
                'service': self.get_service_name(port),
                'version': 'Unknown',
                'banner': f'Error: {str(e)}'
            }

    # 分析banner
    def analyze_banner(self, port, banner, hostname=None):
        result = {
            'service': self.get_service_name(port),
            'version': 'Unknown',
            'banner': banner[:200] if banner else 'No banner'  # 只保留前200字符，避免过长
        }
        if not banner:
            return result

        if port in [80, 8080, 443]:  # HTTP服务，尝试提取服务器类型和版本
            server_match = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if server_match:
                result['version'] = server_match.group(1).strip()
                result['service'] = 'HTTP'
            location_match = re.search(r"Location:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if location_match:
                location = location_match.group(1).strip()
                if location in ['http:///', 'https:///']:
                    correct_host = hostname if hostname else 'Unknown'
                    correct_location = f"https://{correct_host}/"
                    banner = banner.replace(location, correct_location)
                    result['banner'] = banner
                    result['version'] += f" (Location header corrected to {correct_location})"
        elif port == 21:  # FTP服务，尝试提取FTP服务器类型和版本
            match = re.search(r"FTP\s*server\s*ready\s*([^\r\n]+)", banner, re.IGNORECASE)
            if match:
                result['version'] = match.group(1).strip()
        elif port == 25:  # SMTP服务，尝试提取SMTP服务器类型和版本
            match = re.search(r"SMTP\s*server\s*ready\s*([^\r\n]+)", banner, re.IGNORECASE)
            if match:
                result['version'] = match.group(1).strip()
        elif port == 22:
            if 'SSH' in banner:
                result['service'] = 'SSH'
        return result

    # 获取服务名称
    def get_service_name(self, port):
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            8080: 'HTTP-Alt'
        }
        return services.get(port, "Unknown")

# 端口扫描器类
class PortScanner:
    def __init__(self, target, timeout=2, max_threads=100):  # 增加默认超时到2秒
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()  # 线程锁，用于安全地添加结果
        self.service_detector = ServiceDetector()  # 添加服务检测器实例
        
        # 添加域名解析测试
        try:
            socket.gethostbyname(target)
            print(f"目标域名解析成功: {target}")
        except socket.gaierror:
            print(f"警告: 无法解析域名 {target}，请检查网络或域名是否正确")
        except Exception as e:
            print(f"警告: 域名解析异常: {e}")

    # 获取服务名称（调用ServiceDetector的方法）
    def get_service_name(self, port):
        return self.service_detector.get_service_name(port)

    # 获取banner（调用ServiceDetector的方法）
    def get_banner(self, port, hostname=None):
        result = self.service_detector.get_banner(self.target, port, self.timeout, hostname)
        if isinstance(result, dict):
            return result.get('banner', 'No banner')
        return str(result)

    # 扫描单个端口
    def scan_port(self, port, hostname=None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                banner = self.get_banner(port, hostname)
                with self.lock:
                    self.open_ports.append({
                        'port': port,
                        'status': 'open',
                        'service': self.get_service_name(port),
                        'banner': banner
                    })
                print(f"[+]端口{port}开放 - {banner[:50] if banner else 'No banner'}")
            # 添加调试输出，可以看到扫描进度
            # else:
            #     print(f"[-]端口{port}关闭 (错误码: {result})")
        except Exception as e:
            # 可以取消注释下面的行来调试错误
            # print(f"端口{port}扫描异常: {e}")
            pass

    # 扫描多个端口
    def scan_ports(self, port_range, hostname=None):
        # 修复：port_range可能是(min(ports), max(ports))，但端口可能不连续
        # 改为直接使用传入的端口列表
        print(f"\n{'='*60}")
        print(f"开始扫描目标：{self.target}")
        print(f"扫描端口数量：{len(port_range)}")
        print(f"最大线程：{self.max_threads}")
        print(f"超时时间：{self.timeout}")
        print(f"开始时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        threads = []
        # 如果port_range是元组，转换为列表
        if isinstance(port_range, tuple) and len(port_range) == 2:
            start, end = port_range
            ports = list(range(start, end + 1))
        else:
            ports = port_range  # 已经是列表

        for i in range(0, len(ports), self.max_threads):
            batch = ports[i:i + self.max_threads]
            for port in batch:
                t = threading.Thread(target=self.scan_port, args=(port, hostname))
                t.start()  # 开始线程
                threads.append(t)
            for t in threads:
                t.join()  # 等待线程结束
            threads = []

        print(f"\n{'='*60}")
        print(f"扫描完成！开放端口数量：{len(self.open_ports)}")
        print(f"结束时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        if self.open_ports:
            print("开放端口列表：")
            for port_info in self.open_ports:
                print(f"端口：{port_info['port']} - 状态：{port_info['status']} - 服务：{port_info['service']} - Banner：{port_info['banner'][:50]}")
        return self.open_ports

    # 保存扫描结果
    def save_result(self, filename=None):
        if not filename:
            filename = f"scan_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"目标：{self.target}\n")
            f.write(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"开放端口数：{len(self.open_ports)}\n")
            f.write('=' * 60 + '\n\n')
            if self.open_ports:
                f.write(f"{'端口':<8}{'服务':<12}{'banner'}\n") 
                f.write('-' * 60 + '\n')
                for p in sorted(self.open_ports, key=lambda x: x['port']):  # 相当于返回x['port']
                    f.write(f"{p['port']:<8}{p['service']:<12}{p['banner'][:100]}\n")
            else:
                f.write("未发现开放端口\n")
        print(f"结果已保存到{filename}")
        return filename

# 主函数
def main():
    print("=" * 60)
    print("端口扫描系统3.0")
    print("=" * 60)

    if not SCAPY_AVAILABLE:
        print("警告：Scapy库不可用，TCP SYN扫描将无法使用！")
        print("请运行pip install scapy安装scapy库以启用SYN扫描功能")

    while True:
        print("\n请选择模式")
        print("1. TCP全连接扫描")
        print("2. SYN半开放扫描")
        print("3. 退出")
        choice = input("输入选项(1-3): ").strip()

        if choice == '1' or choice == '2':
            scan_type = "tcp" if choice == '1' else "syn" 
            
            if scan_type == "syn" and sys.platform == "win32":
                print("注意，在Windows上运行SYN扫描可能需要管理员权限")
            
            if scan_type == "syn" and not SCAPY_AVAILABLE:
                print("错误：需要安装scapy才能使用SYN扫描")
                continue

            target = input("请输入目标IP或域名：").strip() 
            ports_input = input("请输入端口范围(如80,443或1-1000): ").strip()
            
            ports = []
            if '-' in ports_input:
                start, end = map(int, ports_input.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p.strip()) for p in ports_input.split(',')]

            # 询问域名
            hostname = None
            if any(p in [80, 443, 8080] for p in ports):
                hostname = input("请输入域名（用于HTTP请求，直接回车跳过）：").strip() or None

            print(f"\n开始{scan_type.upper()}扫描{target}的{len(ports)}个端口")
            print("-" * 60)

            start_time = time.time()
            
            # 根据扫描类型执行不同的扫描
            if scan_type == "tcp":
                scanner = PortScanner(target, timeout=3, max_threads=50)  # 增加超时，减少线程数
                results = scanner.scan_ports(ports, hostname)  # 直接传入ports列表
            else:  # syn扫描
                if not SCAPY_AVAILABLE:
                    print("错误：Scapy库不可用，无法进行SYN扫描")
                    continue
                
                print("使用SYN半开放扫描...")
                results = []
                service_detector = ServiceDetector()
                
                for port in ports:
                    # 使用syn_scanner方法扫描
                    is_open, status = service_detector.syn_scanner(target, port, timeout=2)
                    
                    if is_open:  # 端口开放
                        # 获取banner信息
                        banner_info = service_detector.get_banner(target, port, timeout=3, hostname=hostname)
                        
                        port_info = {
                            'port': port,
                            'status': 'open',
                            'service': service_detector.get_service_name(port),
                            'banner': banner_info.get('banner', 'No banner'),
                            'version': banner_info.get('version', 'Unknown')
                        }
                        results.append(port_info)
                        print(f"[+]端口{port}开放 - {port_info['service']} - {port_info['version']}")
                    elif status == "filtered":
                        print(f"[-]端口{port}被过滤")
                    else:
                        print(f"[-]端口{port}关闭")

            total_time = time.time() - start_time

            # 统计结果
            open_ports = [r for r in results if r['status'] == 'open']
            # 注意：TCP全连接扫描不会区分closed和filtered

            print("\n" + "=" * 60)
            print("扫描完成统计")
            print("=" * 60)
            print(f"总扫描时间：{total_time:.2f}秒")
            print(f"开放端口：{len(open_ports)}")

            # 开放端口详情
            if open_ports:
                print("\n开放端口详情：")
                for r in open_ports:
                    print(f"端口 {r['port']}: {r['service']}")
                    if r['banner'] and r['banner'] != 'No banner' and not r['banner'].startswith('Error'):
                        print(f"    Banner: {r['banner'][:100]}")
            else:
                print("\n未发现开放端口")
                print("可能的原因：")
                print("1. 目标防火墙阻止了扫描")
                print("2. 网络连接问题")
                print("3. 超时时间太短")
                print("4. 目标确实没有开放端口")

            # 询问是否保存结果
            save_choice = input("\n是否保存结果？(y/n): ").strip().lower()
            if save_choice == 'y':
                if scan_type == "tcp":
                    scanner.save_result()
                else:
                    # 对于SYN扫描，我们需要创建一个临时的PortScanner对象来保存结果
                    temp_scanner = PortScanner(target, timeout=3, max_threads=50)
                    temp_scanner.open_ports = results
                    temp_scanner.save_result()

        elif choice == '3':
            print("感谢使用，再见！")
            break
        else:
            print("无效选择，请输入1-3！")

if __name__ == "__main__":
    main()
    