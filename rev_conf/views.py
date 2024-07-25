import logging
import re

from django.shortcuts import render, redirect
from django.http import HttpResponse
import subprocess
from django.contrib.auth.decorators import login_required


def is_port_used(config, port):
    # 使用正则表达式来查找配置中是否已存在具有相同端口的 server 块
    pattern = fr"listen\s*{port}\s*;"
    return re.search(pattern, config)


@login_required(login_url="/login/")
def edit_nginx_config(request):
    if request.method == "POST":
        port = request.POST.get("port")
        proxy_pass = request.POST.get("proxy_pass")

        config_file = "/etc/nginx/sites-enabled/default"
        with open(config_file, "r") as file:
            current_config = file.read()

        # 检查端口是否已经被使用
        if is_port_used(current_config, port):
            print(f"端口 {port} 已被使用。")
            return redirect("/api/rev_conf")
            # 可以根据需要进行处理，例如返回错误信息或重定向到错误页面
        else:
            new_config = f"""
server {{
    listen {port};
    server_name localhost;
    location / {{
        proxy_pass {proxy_pass};
    }}
}}"""

            # 打开Nginx配置文件并追加新的配置行
            config_file = "/etc/nginx/sites-enabled/default"
            with open(config_file, "a") as file:
                file.write(new_config)

            # 执行nginx -t来校验配置
            result = subprocess.run(["nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                # 配置合法，重启Nginx服务
                subprocess.run(["systemctl", "restart", "nginx"])
                print("重启Nginx成功")
            else:
                # 配置不合法，可以处理错误情况
                pass

            return redirect("/api/rev_conf")

    # 获取当前Nginx配置中的反向代理规则
    with open("/etc/nginx/sites-enabled/default", "r") as file:
        current_config = file.read()

    proxy_config = []
    pattern = r"listen (\d+);[\s\S]*?proxy_pass (https?://\S+);"
    matches = re.finditer(pattern, current_config)
    for match in matches:
        port = match.group(1)
        proxy_pass = match.group(2)
        proxy_config.append({"port": port, "proxy_pass": proxy_pass})

    delete_port = request.GET.get("del")
    if delete_port:
        pattern = f"server {{\s*listen {delete_port};[\s\S]*?}}[\s\S]*?}}"
        current_config = re.sub(pattern, "", current_config)

        # 检查配置是否有效
        result = subprocess.run(["nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # 配置无效，添加默认 server 块
            current_config += """
server {
    listen 80;
    server_name localhost;
    location / {
        proxy_pass http://127.0.0.1;
    }
}
        """
        config_file = "/etc/nginx/sites-enabled/default"
        with open(config_file, "w") as file:
            file.write(current_config)

    return render(request, "edit_nginx_config.html", {"current_config": current_config, "proxy_config": proxy_config})
