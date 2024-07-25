"""
URL configuration for scanner project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
from django.urls import path, include

import rev_conf.views
from portscan import views as portscanviews
from scanner_api import views as apiViews

urlpatterns = [
    path('dash/', portscanviews.dash),
    path('tool/<str:action>/', portscanviews.tool, name='tool'),
    path('login/', portscanviews.login, name="login"),
    path('register/', portscanviews.register, name="register"),
    path('logout.do', portscanviews.logout, name="logout"),
    path('dash/iplist', portscanviews.ipList, name="iplist"),
    path('dash/addIp.do', portscanviews.addIp, name="addIp"),
    path('dash/delIp.do', portscanviews.delIp, name="delIp"),
    path('dash/editIp.do', portscanviews.editIp, name="editIp"),
    path('dash/about', portscanviews.about, name="about"),
    path('dash/assess', portscanviews.assess, name="assess"),
    path('dash/scheduleList', portscanviews.scheduleList, name="schedule_list"),
    path('dash/falsify', portscanviews.falsify, name="falsify"),
    path('dash/delWeb.do', portscanviews.delWeb, name="delete_web"),
    path('api/nmap.do', apiViews.nmap, name="nmap_api"),
    path('api/show_port_result.do', apiViews.show_scan_results, name="show_port_result"),
    path('api/recheck.do', apiViews.recheck, name="recheck"),
    path('api/ping.do', apiViews.ping, name="ping"),
    path('api/flush_online', apiViews.flush_online, name="flush_online"),
    path('api/fleshWeb', apiViews.fleshWeb, name="flesh_web"),
    path('api/ssh_weak_password_check.do', apiViews.ssh_weak_password_check, name="ssh_weak_password_check"),
    path('api/rdp_weak_password_check.do', apiViews.rdp_weak_password_check, name="rdp_weak_password_check"),
    path('api/get_system_metrics.do', portscanviews.system_metrics, name="system_metrics"),
    path('api/discover.do', apiViews.discover, name="discover"),
    path('api/registrable.do', apiViews.registrable, name="registrable"),
    path('api/ms17_010_check.do', apiViews.ms17_010, name="ms17_010_check"),
    path('api/sql_inject.do', apiViews.sqlmap_check, name="sql_inject"),
    path('api/log4j_check.do', apiViews.log4j_check, name="log4j_check"),
    path('api/receive_linux.do', apiViews.receive_linux, name="receive_linux"),
    path('api/receive_win.do', apiViews.receive_win, name="receive_win"),
    path('api/detail.do', apiViews.getDetail, name="device_brief"),
    path('api/active.do', apiViews.validate_license, name="active"),
    path('api/hik_report.do', apiViews.hik_report, name="hik_report"),
    path('api/addVulScan.do', apiViews.addVulScan, name="addVulScan"),
    path('api/rev_conf', rev_conf.views.edit_nginx_config, name='nginx'),
    path("__debug__/", include("debug_toolbar.urls")),
    path('admin/', portscanviews.noResp),
    # path('/', portscanviews.noResp),
]
