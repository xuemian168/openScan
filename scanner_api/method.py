# 通用方法
import socket
import subprocess

from nmap import PortScanner


# 通用方法——TCP
def is_tcp_port_open(host, port):
    try:
        # 创建一个TCP套接字
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 设置连接超时时间（可选）
            s.settimeout(2)  # 2秒超时，你可以根据需要调整
            # 尝试连接到目标主机的指定端口
            s.connect((host, port))
            return True

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# 通用方法——ICMP
def is_host_alive(ip):
    # 创建ICMP Echo请求包
    # icmp_request = IP(dst=ip) / ICMP()

    # 发送请求并等待响应
    # response = sr1(icmp_request, timeout=5, verbose=False)

    response = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.PIPE)

    # 判断是否收到响应
    if not response.returncode:
        return True  # 主机存活
    else:
        return False  # 主机不存活


# MS17-010漏洞检查
def ms17_010_check(ip):
    print("正在检测MS17-010：", ip)
    port = 445
    nm = PortScanner()
    nm.scan(ip, str(port))

    # 检查是否存在 MS17-010 漏洞
    if '445/tcp' in nm[ip]['tcp']:
        service_info = nm[ip]['tcp']['445']
        if 'script' in service_info and 'smb-vuln-ms17-010' in service_info['script']:
            return True

    return False
