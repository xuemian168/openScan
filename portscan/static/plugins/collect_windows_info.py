#!/usr/bin/env python
# -*- coding:utf-8 -*-
import json
import platform

import requests
import win32com
import wmi


class Win32Info(object):

    def __init__(self):
        self.wmi_obj = wmi.WMI()
        self.wmi_service_obj = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        self.wmi_service_connector = self.wmi_service_obj.ConnectServer(".", "root\cimv2")

    def collect(self):
        data = {
            'os_type': platform.system(),
            'os_release': "%s %s  %s " % (platform.release(), platform.architecture()[0], platform.version()),
            'os_distribution': 'Microsoft',
            'asset_type': 'server'
        }

        # 分别获取各种硬件信息
        data.update(self.get_cpu_info())
        data.update(self.get_ram_info())
        data.update(self.get_motherboard_info())
        data.update(self.get_disk_info())
        data.update(self.get_nic_info())
        data.update(self.get_firewall_status())
        # 最后返回一个数据字典
        return data

    def get_cpu_info(self):
        """
        获取CPU的相关数据，这里只采集了三个数据，实际有更多
        :return:
        """
        data = {}
        cpu_lists = self.wmi_obj.Win32_Processor()
        cpu_core_count = 0
        for cpu in cpu_lists:
            cpu_core_count += cpu.NumberOfCores

        cpu_model = cpu_lists[0].Name  # CPU型号（所有的CPU型号都是一样的）
        data["cpu_count"] = len(cpu_lists)  # CPU个数
        data["cpu_model"] = cpu_model
        data["cpu_core_count"] = cpu_core_count  # CPU总的核数

        return data

    def get_ram_info(self):
        """
        收集内存信息
        :return:
        """
        data = []
        # 这个模块用SQL语言获取数据
        ram_collections = self.wmi_service_connector.ExecQuery("Select * from Win32_PhysicalMemory")
        for ram in ram_collections:  # 主机中存在很多根内存，要循环所有的内存数据
            ram_size = int(int(ram.Capacity) / (1024 ** 3))  # 转换内存单位为GB
            item_data = {
                "slot": ram.DeviceLocator.strip(),
                "capacity": ram_size,
                "model": ram.Caption,
                "manufacturer": ram.Manufacturer,
                "sn": ram.SerialNumber,
            }
            data.append(item_data)  # 将每条内存的信息，添加到一个列表里

        return {"ram": data}  # 再对data列表封装一层，返回一个字典，方便上级方法的调用

    def get_motherboard_info(self):
        """
        获取主板信息
        :return:
        """
        computer_info = self.wmi_obj.Win32_ComputerSystem()[0]
        system_info = self.wmi_obj.Win32_OperatingSystem()[0]
        data = {}
        data['manufacturer'] = computer_info.Manufacturer
        data['model'] = computer_info.Model
        data['wake_up_type'] = computer_info.WakeUpType
        data['sn'] = system_info.SerialNumber
        return data

    def get_disk_info(self):
        """
        硬盘信息
        :return:
        """
        data = []
        for disk in self.wmi_obj.Win32_DiskDrive():  # 每块硬盘都要获取相应信息
            disk_data = {}
            interface_choices = ["SAS", "SCSI", "SATA", "SSD"]
            for interface in interface_choices:
                if interface in disk.Model:
                    disk_data['interface_type'] = interface
                    break
            else:
                disk_data['interface_type'] = 'unknown'

            disk_data['slot'] = disk.Index
            disk_data['sn'] = disk.SerialNumber
            disk_data['model'] = disk.Model
            disk_data['manufacturer'] = disk.Manufacturer
            disk_data['capacity'] = int(int(disk.Size) / (1024 ** 3))
            data.append(disk_data)

        return {'physical_disk_driver': data}

    def get_nic_info(self):
        data = []
        # Query for physical network adapters
        nic_query = "SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True"
        nic_collections = self.wmi_service_connector.ExecQuery(nic_query)

        for nic in nic_collections:
            nic_data = {}
            nic_data['mac'] = nic.MACAddress
            nic_data['model'] = nic.Caption
            nic_data['name'] = nic.Index

            # 筛选物理网卡
            ip_query = f"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index='{nic.Index}'"
            ip_collections = self.wmi_service_connector.ExecQuery(ip_query)

            for ip in ip_collections:
                if ip.IPAddress:
                    nic_data['ip_address'] = ip.IPAddress[0]
                else:
                    nic_data['ip_address'] = ''

                if ip.IPSubnet:
                    nic_data['net_mask'] = ip.IPSubnet[0]
                else:
                    nic_data['net_mask'] = ''

            data.append(nic_data)

        return {'nic': data}

    def get_firewall_status(self):
        try:
            # 创建WMI连接
            wmi_conn = wmi.WMI()
            data = {}
            # 查询防火墙状态
            firewall_settings = wmi_conn.Win32_Service(Name="MpsSvc")[0]

            # 获取防火墙状态
            if firewall_settings.State == "Running":
                firewall_status = 1
            else:
                firewall_status = 0
            data['firewall'] = firewall_status
            return data

        except Exception as e:
            return f"无法获取防火墙状态：{str(e)}"

    def send_data_to_server(self, data, url):
        try:
            headers = {'Content-type': 'application/json'}
            response = requests.post(url, data=json.dumps(data), headers=headers)

            if response.status_code == 200:
                print("Data sent successfully.")
            else:
                print("Failed to send data. Status code:", response.status_code)

        except Exception as e:
            print("Error occurred while sending data:", str(e))


if __name__ == "__main__":
    # 测试代码
    data = Win32Info().collect()

    for key in data:
        print(key, ":", data[key])
    # 指定目标URL
    target_url = "http://127.0.0.1:8000/api/receive_win.do"  # 替换为您的目标URL

    # 发送数据到指定URL
    Win32Info().send_data_to_server(data, target_url)
