#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import json
import re
import subprocess

import requests


def collect():
    filter_keys = ['Manufacturer', 'Serial Number', 'Product Name', 'UUID', 'Wake-up Type']
    raw_data = {}

    for key in filter_keys:
        try:
            res = subprocess.Popen("sudo dmidecode -t system|grep '%s'" % key,
                                   stdout=subprocess.PIPE, shell=True)
            result = res.stdout.read().decode()
            data_list = result.split(':')

            if len(data_list) > 1:
                raw_data[key] = data_list[1].strip()
            else:
                raw_data[key] = ''
        except Exception as e:
            print(e)
            raw_data[key] = ''

    data = dict()
    data['asset_type'] = 'server'
    data['manufacturer'] = raw_data['Manufacturer']
    data['sn'] = raw_data['Serial Number']
    data['model'] = raw_data['Product Name']
    data['uuid'] = raw_data['UUID']
    data['wake_up_type'] = raw_data['Wake-up Type']

    data.update(get_os_info())
    data.update(get_cpu_info())
    data.update(get_ram_info())
    data.update(get_nic_info())
    data.update(get_disk_info())
    return data


def get_os_info():
    """
    获取操作系统信息
    :return:
    """
    distributor = subprocess.Popen("lsb_release -a|grep 'Distributor ID'",
                                   stdout=subprocess.PIPE, shell=True)
    distributor = distributor.stdout.read().decode().split(":")

    release = subprocess.Popen("lsb_release -a|grep 'Description'",
                               stdout=subprocess.PIPE, shell=True)

    release = release.stdout.read().decode().split(":")
    data_dic = {
        "os_distribution": distributor[1].strip() if len(distributor) > 1 else "",
        "os_release": release[1].strip() if len(release) > 1 else "",
        "os_type": "Linux",
    }
    return data_dic


def get_cpu_info():
    """
    获取cpu信息
    :return:
    """
    raw_cmd = 'cat /proc/cpuinfo'

    raw_data = {
        'cpu_model': "%s |grep 'model name' |head -1 " % raw_cmd,
        'cpu_count': "%s |grep  'processor'|wc -l " % raw_cmd,
        'cpu_core_count': "%s |grep 'cpu cores' |awk -F: '{SUM +=$2} END {print SUM}'" % raw_cmd,
    }

    for key, cmd in raw_data.items():
        try:
            result = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            raw_data[key] = result.stdout.read().decode().strip()
        except ValueError as e:
            print(e)
            raw_data[key] = ""

    data = {
        "cpu_count": raw_data["cpu_count"],
        "cpu_core_count": raw_data["cpu_core_count"]
    }

    cpu_model = raw_data["cpu_model"].split(":")

    if len(cpu_model) > 1:
        data["cpu_model"] = cpu_model[1].strip()
    else:
        data["cpu_model"] = ''

    return data


def get_ram_info():
    """
    获取内存信息
    :return:
    """
    raw_data = subprocess.Popen("sudo dmidecode -t memory", stdout=subprocess.PIPE, shell=True)
    raw_list = raw_data.stdout.read().decode().split("\n")
    raw_ram_list = []
    item_list = []
    for line in raw_list:
        if line.startswith("Memory Device"):
            raw_ram_list.append(item_list)
            item_list = []
        else:
            item_list.append(line.strip())

    ram_list = []
    for item in raw_ram_list:
        item_ram_size = 0
        ram_item_to_dic = {}
        for i in item:
            data = i.split(":")
            if len(data) == 2:
                key, v = data
                if key == 'Size':
                    if v.strip() != "No Module Installed":
                        ram_item_to_dic['capacity'] = v.split()[0].strip()
                        item_ram_size = round(v.split()[0])
                    else:
                        ram_item_to_dic['capacity'] = 0

                if key == 'Type':
                    ram_item_to_dic['model'] = v.strip()
                if key == 'Manufacturer':
                    ram_item_to_dic['manufacturer'] = v.strip()
                if key == 'Serial Number':
                    ram_item_to_dic['sn'] = v.strip()
                if key == 'Asset Tag':
                    ram_item_to_dic['asset_tag'] = v.strip()
                if key == 'Locator':
                    ram_item_to_dic['slot'] = v.strip()

        if item_ram_size == 0:
            pass
        else:
            ram_list.append(ram_item_to_dic)

    raw_total_size = subprocess.Popen("cat /proc/meminfo|grep MemTotal ", stdout=subprocess.PIPE, shell=True)
    raw_total_size = raw_total_size.stdout.read().decode().split(":")
    ram_data = {'ram': ram_list}
    if len(raw_total_size) == 2:
        total_gb_size = int(raw_total_size[1].split()[0]) / 1024 ** 2
        ram_data['ram_size'] = total_gb_size

    return ram_data


def get_nic_info():
    try:
        # 使用 ip addr 命令获取网络接口信息
        raw_data = subprocess.Popen("ip addr", stdout=subprocess.PIPE, shell=True)
        raw_data = raw_data.stdout.read().decode().split("\n")

        nic_dic = dict()
        current_nic = None  # 当前正在处理的网卡

        for line in raw_data:
            if line.strip():  # 忽略空行
                if line.startswith("1:") or line.startswith("2:") or line.startswith("3:"):
                    # 新的网卡信息开始
                    if current_nic:
                        nic_name = current_nic.get("name", "")
                        if nic_name and re.match(r'^(eth0|ens\d+)', nic_name) and "ip_address" in current_nic:
                            nic_dic[nic_name] = current_nic

                    current_nic = {"ip_address": []}

                parts = line.strip().split()
                if parts[0] == "inet" and len(parts) >= 2:
                    ip_addr = parts[1].split("/")[0]
                    if ip_addr:
                        current_nic["ip_address"].append(ip_addr)
                elif parts[0] == "link/ether" and len(parts) >= 2:
                    mac_addr = parts[1]
                    if mac_addr:
                        current_nic["mac"] = mac_addr
                elif parts[0] == "2:":
                    nic_name = parts[1]
                    if nic_name:
                        current_nic["name"] = nic_name

        # 处理最后一个网卡信息
        if current_nic:
            nic_name = current_nic.get("name", "")
            if nic_name and re.match(r'^(eth0|ens\d+)', nic_name) and "ip_address" in current_nic:
                nic_dic[nic_name] = current_nic

        nic_list = list(nic_dic.values())
        return {'nic': nic_list}

    except Exception as e:
        print("Error occurred while getting NIC info:", str(e))
        return {'nic': []}


# 测试获取物理网卡信息
physical_nic_info = get_nic_info()
for nic in physical_nic_info['nic']:
    print(nic)


def get_disk_info():
    """
    获取存储信息。
    本脚本只针对ubuntu中使用sda，且只有一块硬盘的情况。
    具体查看硬盘信息的命令，请根据实际情况，实际调整。
    如果需要查看Raid信息，可以尝试MegaCli工具。
    :return:
    """
    raw_data = subprocess.Popen("sudo hdparm -i /dev/sda | grep Model", stdout=subprocess.PIPE, shell=True)
    raw_data = raw_data.stdout.read().decode()
    data_list = raw_data.split(",")
    model = data_list[0].split("=")[1]
    sn = data_list[2].split("=")[1].strip()

    size_data = subprocess.Popen("sudo fdisk -l /dev/sda | grep Disk|head -1", stdout=subprocess.PIPE, shell=True)
    size_data = size_data.stdout.read().decode()
    size = size_data.split(":")[1].strip().split(" ")[0]

    result = {'physical_disk_driver': []}
    disk_dict = dict()
    disk_dict["model"] = model
    disk_dict["size"] = size
    disk_dict["sn"] = sn
    result['physical_disk_driver'].append(disk_dict)

    return result


if __name__ == "__main__":
    # 收集信息功能测试
    data = collect()
    for key in data:
        print(key, ":", data[key])
    # 指定目标URL
    target_url = "http://10.10.10.111/api/receive_linux.do"  # 替换为您的目标URL
    print(data)
    try:
        headers = {'Content-type': 'application/json'}
        response = requests.post(target_url, data=json.dumps(data), headers=headers)

        if response.status_code == 200:
            print("Data sent successfully.")
        else:
            print("Failed to send data. Status code:", response.status_code)

    except Exception as e:
        print("Error occurred while sending data:", str(e))
