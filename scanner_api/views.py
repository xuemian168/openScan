import datetime
import hashlib
import ipaddress
import json
import logging
import platform
import re
import socket
import subprocess
import threading

import paramiko as paramiko
import requests
from bs4 import BeautifulSoup
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from nmap import PortScanner

import portscan.models
import scanner_api.models
from .method import is_host_alive
from .method import is_tcp_port_open
from .method import ms17_010_check
from .models import PortResult


@login_required(login_url="/login/")
def nmap(request):
    if request.method == 'POST':
        scanType = request.POST.get("scanType")
        print("正在进入", scanType)
        if scanType == "ms17_010":
            result = ms17_010_check(request.POST.get('target'))
            return HttpResponse(result)
        elif scanType == "rdp_check":
            return HttpResponse("还没做")
        elif scanType == "hik_report":
            from scanner_api.poc import hik_report
            result = hik_report(request.POST.get('target'))
            return HttpResponse(result)
        elif scanType == "jeecgboot_qurest":
            from scanner_api.poc import jeecgboot
            result = jeecgboot(request.POST.get('target'))
            return HttpResponse(result)
        elif scanType == "h3csecpath_dl":
            from scanner_api.poc import h3C_secpath_dl
            result = h3C_secpath_dl(request.POST.get('target'))
            return HttpResponse(result)

        ip_address = request.POST.get('target')  # 从 POST 请求中获取 IP 地址

        if portscan.models.ips.objects.filter(ip=ip_address).first() is None:
            return HttpResponse("请先添加IP")

        print("正在全端口扫描:" + ip_address)

        try:
            # 创建 PortScanner 对象
            scanner = PortScanner()

            # 扫描指定主机的所有端口
            scanner.scan(ip_address, arguments='-p-')
            print(scanner.command_line())

            # 获取开放端口列表
            open_ports = []

            print(scanner[ip_address].all_tcp())
            open_ports.extend(scanner[ip_address].all_tcp())

            # 返回 JSON 格式的数据
            response_data = {
                "ip_address": ip_address,
                "open_ports": open_ports
            }

            # for port in open_ports:
            #     scan_result = PortResult(ip_address=ip_address, open_port=port)
            #     scan_result.save()

            for port in open_ports:
                # 检查数据库中是否已存在相同的端口结果
                existing_port_result = PortResult.objects.filter(ip_address=ip_address, open_port=port).first()
                if not existing_port_result:
                    scan_result = PortResult(ip_address=ip_address, open_port=port)
                    scan_result.save()

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({"error": str(e)})

        # 如果不是 POST 请求，可以返回错误信息或其他响应
    return JsonResponse({"error": "Invalid request method"})


@login_required(login_url="/login/")
def show_scan_results(request):
    scan_results = PortResult.objects.all()
    return render(request, 'port_result.html', {'scan_results': scan_results})


@login_required(login_url="/login/")
@csrf_exempt
@ratelimit(key='user', rate='60/m', method='GET', block=True)
def recheck(request):
    if request.method == "GET":
        ip = request.GET.get("ip")
        port = request.GET.get("port")
    elif request.method == "POST":
        ip = request.POST.get("ip")
        port = request.POST.get("port")
    print(ip, ":", port)
    result = is_tcp_port_open(ip, int(port))

    # 构建JSON响应
    response_data = {"result": result}

    if not result:
        scanner_api.models.PortResult.objects.filter(ip_address=ip, open_port=port).delete()

    return JsonResponse(response_data)


# 判断主机是否存活
@login_required(login_url="/login/")
@ratelimit(key='user', rate='1/m', method='GET', block=True)
@ratelimit(key='ip', rate='1/m', method='GET', block=True)
def ping(request):
    ip = request.GET.get("ip")
    print("尝试Ping:" + ip)
    result = is_host_alive(ip)
    response_data = {"result": result}
    return JsonResponse(response_data)
    # 需要禁止GET


def flush_online(request):
    offlines = []
    try:
        # 获取所有未被移除的 IP 地址
        ips2 = portscan.models.ips.objects.filter(remove=0)

        # 使用多线程处理 ICMP ping 操作
        results = []

        def ping_host(ip):
            try:
                # 判断系统类型并执行对应命令
                if platform.system() == "Windows":
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.PIPE)
                elif platform.system() == "Linux":
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE)
                if result.returncode == 0:
                    exist_host = portscan.models.ips.objects.filter(ip=ip).first()
                    portscan.models.ips.objects.filter(ip=ip).update(online=1)
                    results.append({'ip': ip, 'status': 'Online'})

                else:
                    offlines.append(ip)
                    portscan.models.ips.objects.filter(ip=ip).update(online=0)
                    results.append({'ip': ip, 'status': 'Offline'})
            except Exception as e:
                results.append({'ip': ip, 'status': e})

        threads = []
        for ip3 in ips2:
            thread = threading.Thread(target=ping_host, args=(ip3.ip,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if offlines:
            from scanner_api.ding import ding_diy
            result = "\n\n -  ".join(offlines)
            dingData = {
                "msgtype": "markdown",
                "markdown": {
                    "title": "设备离线通知",
                    "text": "## 设备离线通知  \n **以下设备离线：** \n\n - " + result,
                },
                "at": {"isAtAll": True}
            }
            ding_diy(dingData)

        return JsonResponse(results, safe=False)

    except Exception as e:
        return JsonResponse({'error': str(e)})


@csrf_exempt
def ssh_weak_password_check(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        ip = data.get("ip")
        port = data.get("port")
        print("尝试爆破SSH：", ip, ":", port)
        username_list = ['root']  # 用户名列表
        password_list = ['root', '123456', '123123']  # 密码列表

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            for username in username_list:
                for password in password_list:
                    try:
                        ssh_client.connect(ip, port=port, username=username, password=password)
                        # 如果连接成功，表示SSH弱口令验证通过
                        return JsonResponse(
                            {'success': True, 'message': 'SSH弱口令验证通过', 'password': username + '/' + password})
                    except paramiko.AuthenticationException:
                        # 认证失败，继续尝试下一组用户名和密码
                        pass

            # 如果所有用户名和密码组合都失败，表示SSH弱口令验证未通过
            return JsonResponse({'success': False, 'message': 'SSH弱口令验证未通过'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    else:
        return JsonResponse({'success': False, 'message': '只接受POST请求'})


def rdp_weak_password_check(request):
    # 还没写
    return None


@login_required(login_url="/login/")
def discover(request):
    if request.method == "POST":
        ip_start = request.POST.get("ip_start")
        ip_end = request.POST.get("ip_end")
        ip_end = 24

        try:
            # 使用 ipaddress 模块生成完整的 IP 地址列表
            ip_range = ipaddress.IPv4Network(f"{ip_start}/{ip_end}", strict=False)
            ip_list = [str(ip) for ip in ip_range]

            # 使用多线程处理 Ping 操作
            results = []

            def ping_host(ip):
                try:
                    # 判断系统类型并执行对应命令
                    if platform.system() == "Windows":
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.PIPE)
                    elif platform.system() == "Linux":
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE)
                    if result.returncode == 0:
                        exist_host = portscan.models.ips.objects.filter(ip=ip).first()
                        if not exist_host:
                            portscan.models.ips.objects.create(ip=ip, owner="无", description="无", online=1)
                        results.append({'ip': ip, 'status': 'Online'})
                    else:
                        results.append({'ip': ip, 'status': 'Offline'})
                except Exception as e:
                    results.append({'ip': ip, 'status': 'Error'})

            threads = []
            for ip in ip_list:
                thread = threading.Thread(target=ping_host, args=(ip,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            # 返回 JSON 格式的结果
            return JsonResponse(results, safe=False)

        except Exception as e:
            return JsonResponse({'error': str(e)})

    return JsonResponse({'error': 'Invalid request method'})


@login_required(login_url="/login/")
def registrable(request):
    if request.method == "POST":
        is_registrable = portscan.models.Settings.objects.filter(title="registrable").first().status
        if is_registrable:
            portscan.models.Settings.objects.filter(title="registrable").update(status=0)
        else:
            portscan.models.Settings.objects.filter(title="registrable").update(status=1)
        return HttpResponse("修改注册成功")
    else:
        return HttpResponse("不允许GET请求")


@csrf_exempt
@login_required(login_url="/login/")
def ms17_010(request):
    if request.method == "POST":
        data = json.loads(request.body.decode('utf-8'))
        target = data.get("ip")
        print(target)

        # 使用 subprocess 执行 Nmap 漏洞扫描命令
        try:
            nmap_command = ["nmap", "--script", "smb-vuln-ms17-010", "-p445", target]
            result = subprocess.run(nmap_command, capture_output=True, text=True, check=True)

            # 检查扫描结果中是否包含漏洞信息
            output = result.stdout
            if "Host is likely vulnerable" in output:
                return JsonResponse({'result': 'MS17-010'})
            else:
                return JsonResponse({'result': 'No'})

        except subprocess.CalledProcessError as e:
            return JsonResponse({'error': 'failed'})

    return JsonResponse({'error': 'error'})


@csrf_exempt
def hik_report(request):
    from scanner_api.poc import hik_report
    if request.method == "POST":
        host = request.POST.get('target')
        result = hik_report(host)
        return JsonResponse({'result': result})


@csrf_exempt
@login_required(login_url="/login/")
def sqlmap_check(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        print(url)

        # 使用SQLMAP执行检查，这里请根据你的SQLMAP安装路径进行调整
        sqlmap_command = f'sqlmap -u {url} --batch'
        result = subprocess.run(sqlmap_command, shell=True, capture_output=True, text=True)

        # 获取SQLMAP的输出结果
        sqlmap_output = result.stdout

        return JsonResponse({'result': sqlmap_output})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
@login_required(login_url="/login/")
def log4j_check(request):
    target_host = request.POST.get("ip")
    target_port = int(request.POST.get("port"))
    print("正在尝试Log4j:", target_host, target_port)
    # 构造恶意的Log4j消息，触发漏洞
    payload = b'GET / HTTP/1.1\r\n' \
              b'Host: example.com\r\n' \
              b'User-Agent: () { :;}; /bin/bash -c \'ping -c 3 8.8.8.8\'\r\n' \
              b'Accept: */*\r\n\r\n'

    # 创建套接字并发送数据
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_host, target_port))
    sock.sendall(payload)

    # 接收响应数据并检查是否存在漏洞
    data = sock.recv(1024)
    if b'HTTP/1.1 200 OK' in data and b'PING' in data:
        print('[+] 目标存在漏洞！')
        return HttpResponse("yes")
    else:
        print('[-] 目标不存在漏洞。')
        return HttpResponse("No")


@csrf_exempt
def receive_linux(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        # print(data.get("os_type"))
        # 将数据存储到数据库中
        if data.get("os_type") == 'Linux':
            os_type = 0
        elif data.get("os_type") == 'Windows':
            os_type = 1
        os_release = data.get("os_release")
        cpu_count = data.get("cpu_core_count")
        cpu_model = data.get("cpu_model")
        # print(data)
        nic_info_list = data.get('nic', [])
        nic_count = len(nic_info_list)
        for nic in nic_info_list:
            ip = nic['ip_address'][0]
            print(ip)
            mac = nic['mac']
            nic_model = nic['name']
            device_id = portscan.models.ips.objects.get(ip=ip).id
            print(device_id)
            if device_id:
                scanner_api.models.asset.objects.filter(device_id_id=device_id).all().update(status=0)
                scanner_api.models.asset.objects.create(
                    os_type=os_type,
                    os_release=os_release,
                    cpu_count=cpu_count,
                    cpu_model=cpu_model,
                    device_id_id=device_id,
                    mac=mac,
                    model=nic_model,
                    nic_count=nic_count,
                    status=1,
                )
            return JsonResponse({"result": "成功"})
        return JsonResponse({'status': '资产详情数据收集成功'})
    else:
        return JsonResponse({'status': '不合法的请求'}, status=400)


@csrf_exempt
def receive_win(request):
    if request.method == "POST":
        data = json.loads(request.body.decode('utf-8'))
        os_type = None
        if data.get("os_type") == 'Linux':
            os_type = 0
        elif data.get("os_type") == 'Windows':
            os_type = 1
        os_release = data.get("os_release")
        cpu_count = data.get("cpu_count") * data.get("cpu_core_count")
        cpu_model = data.get("cpu_model")
        firewall_status = data.get("firewall")
        # 获取所有物理网卡信息
        nic_info_list = data.get('nic', [])
        nic_count = len(nic_info_list)
        print(nic_info_list)
        # 入库
        for nic in nic_info_list:
            ip = nic['ip_address']
            mac = nic['mac']
            nic_model = nic['model']
            try:
                device_id = portscan.models.ips.objects.get(ip=ip).id
            except portscan.models.ips.DoesNotExist:
                device_id = None
            if device_id:
                scanner_api.models.asset.objects.filter(device_id_id=device_id).all().update(status=0)
                scanner_api.models.asset.objects.create(os_type=os_type,
                                                        os_release=os_release,
                                                        cpu_count=cpu_count,
                                                        cpu_model=cpu_model,
                                                        device_id_id=device_id,
                                                        mac=mac,
                                                        model=nic_model,
                                                        nic_count=nic_count,
                                                        status=1,
                                                        firewall=firewall_status
                                                        )
                print("add Windows Succeed")
                return JsonResponse({"result": "成功"})
        return HttpResponse("ok")
    else:
        return HttpResponse("请求不合法")


@csrf_exempt
@login_required(login_url="/login/")
def getDetail(request):
    id = request.GET.get("id")
    detail = scanner_api.models.asset.objects.filter(device_id_id=id, status=1).first()
    if detail.os_type == 0:
        os = "Linux"
    elif detail.os_type == 1:
        os = "Windows"
    if detail:
        asset_data = {
            'os_type': os,
            'os_release': detail.os_release,
            'device_id': detail.device_id.id,  # 获取外键关联的 id
            'cpu_count': detail.cpu_count,
            'cpu_model': detail.cpu_model,
            'model': detail.model,
            'mac': detail.mac,
            'nic_count': detail.nic_count,
        }

        return JsonResponse(asset_data)
    else:
        return JsonResponse({'message': 'Asset not found'}, status=404)


@csrf_exempt
def fleshWeb(request):
    # print("正在执行fleshWeb")
    # logging.INFO("正在执行fleshWeb操作")
    allObj = scanner_api.models.webSite.objects
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    for web in allObj.all():
        count = 0
        url = web.url
        bef = web.aft_long
        id = web.id
        owner = web.owner
        response = requests.get(url, headers=headers)
        respond_code = response.status_code
        print(respond_code, response)
        byte_length = len(response.content)
        response.encoding = 'utf-8'
        # 解析HTML内容
        soup = BeautifulSoup(response.text, 'html.parser')
        # 提取标题
        title = soup.title.string63

        
        print(soup)
        if ((int(byte_length) - int(bef) > 200) or (int(bef) - int(byte_length) > 200)) and title != web.title:
            status = 2
            from scanner_api.ding import ding_diy
            dingData = {
                "msgtype": "markdown",
                "markdown": {
                    "title": "篡改告警（监测代码）",
                    "text": "## 篡改告警 \n **点击进入源站:** \n"
                            " > [" + title + "](" + url + ") \n\n "
                                                          "建议使用无痕模式！ \n\n "
                                                          "责任人：" + owner + "\n" +
                            "\n > 告警时间：" +
                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
                "at": {"isAtAll": True}
            }
            ding_diy(dingData)
        else:
            status = 1

        keywords = scanner_api.models.keywords.objects.values_list('value', flat=True)
        # 将查询集转换为列表
        keywords = list(keywords)
        # 使用正则表达式进行全文搜索
        for keyword in keywords:
            # pattern = re.compile(r'\b{}\b'.format(re.escape(keyword)), re.IGNORECASE)
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            if pattern.search(response.text):
                count = count + 1
                from scanner_api.ding import ding_diy
                dingData = {
                    "msgtype": "markdown",
                    "markdown": {
                        "title": "篡改告警（监测关键字）",
                        "text": "## 篡改告警 \n 监测到违禁词" + str(count) + "个！ \n **点击进入源站:** \n"
                                                                             " > [" + title + "](" + url + ") \n\n "
                                                                                                           "建议使用无痕模式！ \n\n "
                                                                                                           "责任人：" + owner + "\n" +
                                "\n > 告警时间：" +
                                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    },
                    "at": {"isAtAll": True}
                }
                ding_diy(dingData)

                print(f'页面包含关键字 "{keyword}"')
            else:
                # print(f'页面不包含关键字 "{keyword}"')
                pass

        allObj.filter(id=id).update(respond_code=respond_code,
                                    bef_long=bef, aft_long=byte_length,
                                    status=status, title=title,
                                    keyword=count, )
    return JsonResponse({"result": "ok"})


def generate_license(mac_address, expiration_date):
    # 合并 MAC 地址和过期日期，并添加随机密钥
    license_data = f"{mac_address}{expiration_date}xuemian168.com"

    # 使用哈希函数（例如 SHA-256）生成许可密钥
    license_key = hashlib.sha256(license_data.encode()).hexdigest()

    return license_key


def validate_license(request):
    if request.method == 'POST':
        data = request.POST
        license_key = data.get('license')
        expected_mac_address = data.get('mac').upper()
        expected_expiration_date = data.get('expire')

        expected_license_key = generate_license(expected_mac_address, expected_expiration_date)

        # 验证许可密钥
        if license_key == expected_license_key:
            response_data = {'message': '许可密钥验证通过，产品已激活。'}
            portscan.models.license.objects.filter(id=1).update(license_key=license_key,
                                                                expire_time=expected_expiration_date,
                                                                status=1)
            return JsonResponse(response_data)
        else:
            response_data = {'message': '许可密钥验证失败，产品未激活。'}
            return JsonResponse(response_data)
    else:
        response_data = {'message': '只接受 POST 请求。'}
        return JsonResponse(response_data)


def daily(request):
    print("生成日报")
    # 获取日报
    ips = portscan.models.ips.objects
    devices_info = scanner_api.models.asset.objects
    ports = scanner_api.models.PortResult.objects
    webs = scanner_api.models.webSite.objects

    online_sum = str(len(ips.filter(online=1).all()))
    offline_sum = str(len(ips.filter(online=0).all()))
    web_online = str(len(webs.filter(respond_code=200).all()))
    web_offline = str(webs.exclude(respond_code=200).count())
    current_date = datetime.datetime.now().strftime("%Y年%m月%d日")
    all_port = str(ports.all().count())
    rdp_port = str(ports.filter(open_port=3389).count())
    ssh_port = str(ports.filter(open_port=22).count())

    from scanner_api.ding import ding_diy
    report = {
        "msgtype": "markdown",
        "markdown": {
            "title": current_date + "日报",
            "text": " ## " + current_date + "日报 \n\n"
                                            " - 在线主机数：" + online_sum + " \n\n "
                                                                            " - 离线主机数：" + offline_sum + " \n\n "
                                                                                                             " - 在线站点数：" + web_online + " \n\n "
                                                                                                                                             " - 离线站点数：" + web_offline + " \n\n"
                                                                                                                                                                              " \n\n 开放端口总数：" + all_port + " \n\n"
                                                                                                                                                                                                                 "RDP开放：" + rdp_port + " ,SSH开放" + ssh_port
        },
        "at": {
            "isAtAll": True
        }
    }
    ding_diy(report)


def licence_check(request):
    today = datetime.date.today()
    expired_record = portscan.models.license.objects.filter(id=1).first()
    expire_time = expired_record.expire_time
    records = datetime.date.fromisoformat(expire_time)
    if records < today:
        # 过期
        portscan.models.license.objects.filter(id=1).update(status=0)
        print("密钥已过期")
    else:
        pass


@login_required(login_url="/login")
def addVulScan(request):
    if request.method == "POST":
        target = request.POST.get("target")
        # vulId = request.POST.getlist("vulId")
        print(target)
        # print(vulId)
        return HttpResponse("创建")
    else:
        return HttpResponse("非法调用")
