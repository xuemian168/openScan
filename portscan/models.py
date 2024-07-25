from django.db import models


# 网页设置
class Settings(models.Model):
    title = models.CharField(max_length=12)  # 设置名称
    status = models.SmallIntegerField(null=True, blank=True)  # 值1
    value = models.CharField(null=True, blank=True, verbose_name="设置的值，可为空", max_length=128)  # 值2


class ips(models.Model):
    ip = models.GenericIPAddressField(protocol='IPv4')  # address
    online = models.BooleanField(default=False)  # online status
    # port = models.IntegerField(null=True, blank=True)  # 开放端口
    owner = models.CharField(max_length=25, null=True, blank=True)  # 责任人
    description = models.CharField(max_length=256, null=True, blank=True)  # 备注
    remove = models.IntegerField(default=0)  # 删除为1 未删除为0


class license(models.Model):
    status = [
        (0, "失效"),
        (1, "激活")
    ]
    # 格式example: 2023-09-25
    expire_time = models.CharField(max_length=11, verbose_name="过期时间")
    license_key = models.CharField(max_length=64, verbose_name="密钥")
    status = models.SmallIntegerField(choices=status, verbose_name="状态")


