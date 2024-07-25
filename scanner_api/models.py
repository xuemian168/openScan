from django.db import models

import portscan.models


class PortResult(models.Model):
    ip_address = models.CharField(max_length=255)
    open_port = models.IntegerField()

    def __str__(self):
        return f"{self.ip_address}:{self.open_port}"


class asset(models.Model):
    osTypes = [
        (0, "Linux"),
        (1, "Windows"),
        (2, "Other"),
    ]
    status = [
        (0, "过期"),
        (1, "最新"),
    ]
    os_type = models.SmallIntegerField(choices=osTypes, verbose_name="系统类型")
    os_release = models.CharField(max_length=64)
    device_id = models.ForeignKey(portscan.models.ips, on_delete=models.CASCADE, default=4)
    cpu_count = models.SmallIntegerField(blank=True, null=True, verbose_name="CPU总数")
    cpu_model = models.CharField(max_length=255)
    model = models.CharField(max_length=255, verbose_name="型号")
    mac = models.CharField(max_length=64, verbose_name="MAC地址")
    nic_count = models.SmallIntegerField(verbose_name="网卡总数", default=1)
    status = models.SmallIntegerField(verbose_name="更新状态", choices=status, default=0)
    firewall = models.SmallIntegerField(verbose_name="防火墙状态", default=0)


class webSite(models.Model):
    status = [
        (0, "停止监控"),
        (1, "正常"),
        (2, "异常"),
    ]
    url = models.CharField(max_length=64, verbose_name="监测的网站地址")
    title = models.CharField(max_length=64, verbose_name="网站标题", default="未捕获")
    bef_long = models.IntegerField(verbose_name="之前字节长度", blank=True, null=True)
    aft_long = models.IntegerField(verbose_name="当前字节长度")
    respond_code = models.SmallIntegerField(verbose_name="网页状态")
    owner = models.CharField(max_length=10, verbose_name="责任人", default="暂无")
    keyword = models.IntegerField(verbose_name="触发关键词数量", default=0)
    status = models.SmallIntegerField(choices=status, verbose_name="当前状态")


class keywords(models.Model):
    value = models.CharField(max_length=16, verbose_name="关键词")
    time = models.DateTimeField(verbose_name="添加时间", auto_now=True)


class vulList(models.Model):
    name = models.CharField(max_length=64, verbose_name="漏洞名称")
    cve = models.CharField(max_length=32, verbose_name="CVE漏洞编号", null=True, blank=True)
    methodName = models.CharField(max_length=32, verbose_name="对应方法名", null=True, blank=True)


class scheduleList(models.Model):
    target = models.CharField(max_length=128, verbose_name="扫描目标")
    startTime = models.DateTimeField(null=True, blank=True)


    def __str__(self):
        return self.target
