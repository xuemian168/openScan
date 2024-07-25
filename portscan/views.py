import csv
import re

import psutil as psutil
import requests
from Crypto.PublicKey import RSA
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django_ratelimit.decorators import ratelimit

import portscan.models
import scanner_api.models
from portscan import models
from portscan.forms import CSVUploadForm


@ratelimit(key='ip', rate='3/m', block=True)
def noResp(request):
    from scanner_api.ding import dingding_post
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    user_agent = request.META.get('HTTP_USER_AGENT')
    path = request.path
    dingding_post(ip + "正在尝试寻找登录入口\n" + user_agent + "\n 请注意审查！" + path)
    return HttpResponse("404 Not Found")


# 用户管理开始

def register(request):
    registrable = models.Settings.objects.filter(title="registrable").first().status
    print(registrable)
    if registrable == 0:
        return HttpResponse("不允许注册")
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        repass = request.POST.get("repassword")
        if repass != password:
            return HttpResponse("输入有误")
        if User.objects.filter(username=username):
            return HttpResponse("用户名已被占用")
        User.objects.create_user(username=username, password=password)
        return redirect("/login", {"msg": "注册成功"})
    return render(request, "register.html")


# def login(request):
#     return render(request, "login.html")

# @ratelimit(key='ip', rate='8/m', block=True)
def login(request):
    print("进入登陆方法")
    from scanner_api.ding import dingding_post
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    user_agent = request.META.get('HTTP_USER_AGENT')
    # 生成随机验证码6位
    import random
    if request.method == "POST":

        valid_code = request.POST.get("validCode")
        try:
            code = request.session.get("code")
            print("正确验证码：", code, valid_code)
        except:
            return HttpResponse("验证码失效")

        if valid_code != code:
            return HttpResponse("验证码错误")

        private_key = RSA.import_key(request.session.get('private_key').encode('utf-8'))

        from Crypto.Cipher import PKCS1_v1_5
        cipher = PKCS1_v1_5.new(private_key)

        print("Private key used for decryption:", private_key)

        import base64
        decoded_username = base64.b64decode(request.POST.get('username'))
        decoded_password = base64.b64decode(request.POST.get('password'))

        # 进行解密
        try:
            username = cipher.decrypt(decoded_username, None).decode('utf-8')
            password = cipher.decrypt(decoded_password, None).decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return HttpResponse("Incorrect decryption.")

        userobj = auth.authenticate(username=username, password=password)
        if userobj is not None:
            auth.login(request, userobj)
            request.session["username"] = username
            request.session.set_expiry(600)  # 设置 session 存活期
            # if request.session.session_key:
            #     from requests import Session
            #     Session.objects.filter(session_key=request.session.session_key).delete()
            print(username + "登录成功")
            dingding_post(ip + " 登陆成功 " + request.session.get("username") + "!")
            return redirect("/dash/", {"user", userobj})
        else:
            return HttpResponse("登录错误")
    elif request.method == "GET":
        code = '%06d' % random.randint(0, 999999)
        print("生成了验证码", code)
        request.session["code"] = code  # 存储的也是 key-value 键值对

        from datetime import datetime
        dingding_post(datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S") + "\n" + ip + "正在尝试登陆本系统\n" + user_agent + "\n\n验证码为： " + code + "(2分钟内有效)")
        # print("生成密钥对")
        private_key, public_key = generate_rsa_keypair()
        request.session["private_key"] = private_key.decode('utf-8')
        request.session.set_expiry(60)  # 设置 session 存活期

        return render(request, "login.html", {"public_key": public_key.decode('utf-8'), "msg": "welcome"})


def generate_rsa_keypair(bits=2048):
    from Crypto.PublicKey import RSA
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_decrypt(encrypted_data, private_key):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    import base64
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted_data = cipher_rsa.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data


def logout(request):
    from scanner_api.ding import dingding_post
    username = request.user.get_username()
    dingding_post(username + " 已注销登录")
    auth.logout(request)
    request.session.flush()
    return redirect("/login/", {"msg": "注销成功"})


def validCode(request):
    # 生成随机验证码6位
    import random
    from scanner_api.ding import dingding_post
    code = '%06d' % random.randint(0, 999999)
    # 存储到session
    request.session["code"] = code  # 存储的也是 key-value 键值对
    request.session.set_expiry(60)  # 设置 session 存活期 单位是秒
    # 调用钉钉接口 发送验证码
    dingding_post(code)
    return JsonResponse({"msg": "ok", "code": 200})


# 用户管理结束

# 面板开始
@login_required(login_url="/login/")
def dash(request):
    # username = request.session.get("username")  # 当前用户名
    activity = portscan.models.license.objects.get(id=1).status
    return render(request, "dash.html", {"activity": activity})


@login_required(login_url="/login/")
def ipList(request):
    if request.method == "POST":
        ip = request.POST.get("ip")
        ips_result = models.ips.objects.filter(ip=ip)
        return render(request, "iplist.html", {"list": ips_result})
    elif request.method == "GET":
        owner = request.GET.get("owner")
        portlist = scanner_api.models.PortResult.objects.all()
        if owner:
            ips_result = models.ips.objects.filter(remove=0, owner=owner)
        else:
            ips_result = models.ips.objects.filter(remove=0)
        return render(request, "iplist.html", {"list": ips_result, "owner": owner, "port_list": portlist})


@login_required(login_url="/login/")
def addIp(request):
    if request.method == "POST":
        newip = request.POST.get("newip")
        owner = request.POST.get("owner")
        description = request.POST.get("description")
        print("添加IP：", newip, owner, description)
        if models.ips.objects.filter(ip=newip).first():
            return HttpResponse("IP已存在")
        models.ips.objects.create(ip=newip, owner=owner, description=description)
        return redirect("/dash/iplist")
    else:
        return HttpResponse("error")


@login_required(login_url="/login/")
def delIp(request):
    delIpId = request.GET.get("id")
    ip = models.ips.objects.get(id=delIpId).ip
    from scanner_api.ding import dingding_post
    dingding_post("正在删除对" + ip + "的管控")
    models.ips.objects.filter(id=delIpId).all().update(remove=1)
    return redirect("/dash/iplist")


@login_required(login_url="/login/")
def editIp(request):
    result = "错误"
    response_data = {"result": result}
    if request.method == "POST":
        ip = request.POST.get("ip")
        new_owner = request.POST.get("new_owner")
        new_description = request.POST.get("new_description")
        models.ips.objects.filter(ip=ip).update(owner=new_owner, description=new_description)
        response_data = {"result": "成功"}
        return redirect("/dash/iplist")
    else:
        return JsonResponse(response_data)


@login_required(login_url="/login/")
def tcping(request):
    return render(request, "tcping.html")


@login_required(login_url="/login/")
def about(request):
    if request.method == "POST":
        plicense = request.POST.get("license")

        # 解密代码

    if request.method == "GET":
        license_k = models.license.objects.all()
        registrable = models.Settings.objects.filter(title="registrable").first().status
        ding_webhook = models.Settings.objects.get(title="ding_webhook").value
        ding_secret = models.Settings.objects.get(title="ding_secret").value
        return render(request, "about.html", {"registrable": registrable, "license": license_k,
                                              "ding_webhook": ding_webhook, "ding_secret": ding_secret})


@login_required(login_url="/login/")
def scheduleList(request):
    if request.method == "GET":
        portlist = scanner_api.models.PortResult.objects.all()
        vulList = scanner_api.models.vulList.objects.all()
        ipList = portscan.models.ips.objects.all()
        return render(request, "schedule.html", {"port_list": portlist, "vulList": vulList, "ipList": ipList})
    elif request.method == "POST":
        tarip = request.POST.get("ip")
        portlist = scanner_api.models.PortResult.objects.filter(ip_address__icontains=tarip).all()
        return render(request, "schedule.html", {"port_list": portlist})


def system_metrics(request):
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent
    online_hosts = models.ips.objects.filter(online=1, remove=0).count()
    offline_hosts = models.ips.objects.filter(online=0, remove=0).count()
    attention_ports = scanner_api.models.PortResult.objects.filter(open_port=3389 or 22).count()
    open_ports = scanner_api.models.PortResult.objects.all().count()

    # 构建响应数据
    data = {
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "online_hosts": online_hosts,
        "offline_hosts": offline_hosts,
        "attention_ports": attention_ports,
        "open_ports": open_ports,
        # 添加其他系统指标
    }

    # 将数据转换为 JSON 格式并返回
    return JsonResponse(data)


def assess(request):
    if request.method == "GET":
        assess_list = scanner_api.models.asset.objects.filter(status=1)
        ips = []
        for asset in assess_list:
            ips.append(portscan.models.ips.objects.filter(id=asset.device_id_id).first().ip)
        ips.reverse()
        # 存入数组 前端用pop取出
        return render(request, "assess.html", {"assess_list": assess_list, "ips": ips})
    elif request.method == "POST":
        keyword = request.POST.get("keyword")
        query = Q(os_release__icontains=keyword) | Q(cpu_model__icontains=keyword) | Q(model__icontains=keyword)
        assess_list = scanner_api.models.asset.objects.filter(status=1)
        assess_list = assess_list.filter(query)
        ips = []
        for asset in assess_list:
            ips.append(portscan.models.ips.objects.filter(id=asset.device_id_id).first().ip)
        ips.reverse()
        return render(request, "assess.html", {"assess_list": assess_list, "ips": ips, "keyword": keyword})


@login_required(login_url="/login/")
def falsify(request):
    count = 0
    webObj = scanner_api.models.webSite.objects
    keyObj = scanner_api.models.keywords.objects.all()
    form = CSVUploadForm(request.POST, request.FILES)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    if request.method == "POST":
        try:
            url = request.POST.get("url")
            if webObj.filter(url=url, status=0).first():
                return HttpResponse("已存在")
            owner = request.POST.get("owner")
            response = requests.get(url, headers=headers)
            respond_code = response.status_code
            print(respond_code, response)
            # 检查是否发生请求错误
            byte_length = len(response.content)

            keywords = scanner_api.models.keywords.objects.values_list('value', flat=True)
            # 将查询集转换为列表
            keywords = list(keywords)
            # 使用正则表达式进行全文搜索
            for keyword in keywords:
                pattern = re.compile(r'\b{}\b'.format(re.escape(keyword)), re.IGNORECASE)
                if pattern.search(response.text):
                    count = count + 1
                    print(f'页面包含关键字 "{keyword}"')
                else:
                    print(f'页面不包含关键字 "{keyword}"')

            webObj.create(url=url,
                          owner=owner,
                          respond_code=respond_code,
                          aft_long=byte_length,
                          bef_long=0,
                          status=1,
                          keyword=count, )
        except:
            if form.is_valid():
                csv_file = request.FILES['csv_file']
                # 读取CSV文件并将数据写入数据库
                # 读取CSV文件并处理数据
                decoded_csv = csv_file.read().decode('utf-8')
                csv_reader = csv.reader(decoded_csv.splitlines())

                for row in csv_reader:
                    if row:  # 确保行不为空
                        keyword_value = row[0]  # 假设关键字在第一列
                        if scanner_api.models.keywords.objects.filter(value=keyword_value).first() is None:
                            scanner_api.models.keywords.objects.create(value=keyword_value)

        result = webObj.exclude(status=0)
        return redirect("/dash/falsify", {"result": result, "form": form, "keywords": keyObj})
    elif request.method == "GET":
        result = webObj.exclude(status=0)
        return render(request, "falsify.html", {"result": result, "form": form, "keywords": keyObj})


@login_required(login_url="/login/")
def delWeb(request):
    id = request.GET.get("id")
    scanner_api.models.webSite.objects.filter(id=id).update(status=0)
    return redirect('/dash/falsify')


@login_required(login_url="/login/")
def tool(request, action):
    import subprocess
    if request.method == 'POST':
        result = ""
        if action == 'ping':
            ip = request.POST.get('target')
            result = subprocess.check_output(['ping', '-c', '4', ip])

        elif action == 'tcping':
            ip = request.POST.get('ip')
            port = request.POST.get('port')
            try:
                # 调用本地的 tcping 工具
                cmd = ['tcping', '-t', '1', ip, port]
                result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
                # 格式化输出结果
                formatted_result = result.replace('\n', '<br>')  # 替换换行符为HTML换行标签
                return JsonResponse({"result": formatted_result})
            except subprocess.CalledProcessError as e:
                result = e.output  # 获取错误输出
                return JsonResponse({"error": result})

        elif action == 'nslookup':
            target = request.POST.get('target')
            result = subprocess.check_output(['nslookup', target])

        elif action == 'whois':
            domain = request.POST.get('target')
            result = subprocess.check_output(['whois', domain])

        elif action == 'traceroute':
            ip = request.POST.get('target')
            result = subprocess.check_output(['traceroute', ip])

        return JsonResponse({"result": result.decode('utf-8')})
    elif request.method == "GET":
        return render(request, "tools.html")
    return JsonResponse({"error": "Invalid method"})
