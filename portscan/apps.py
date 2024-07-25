from django.apps import AppConfig


class PortscanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'portscan'

    # def ready(self):
    #     # 在应用程序加载时执行操作
    #     import portscan.models