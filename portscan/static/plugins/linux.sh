#!/bin/bash

# 收集硬件信息
function collect_info {
    filter_keys=("Manufacturer" "Serial Number" "Product Name" "UUID" "Wake-up Type")
    raw_data=()

    for key in "${filter_keys[@]}"; do
        result=$(sudo dmidecode -t system | grep "$key")
        if [ -n "$result" ]; then
            value=$(echo "$result" | awk -F: '{print $2}' | awk '{$1=$1};1')
            raw_data+=("$key: $value")
        else
            raw_data+=("$key: ")
        fi
    done

    asset_type="server"
    manufacturer=""
    sn=""
    model=""
    uuid=""
    wake_up_type=""

    for data in "${raw_data[@]}"; do
        key=$(echo "$data" | awk -F: '{print $1}' | awk '{$1=$1};1')
        value=$(echo "$data" | awk -F: '{print $2}' | awk '{$1=$1};1')
        case $key in
            "Manufacturer") manufacturer="$value" ;;
            "Serial Number") sn="$value" ;;
            "Product Name") model="$value" ;;
            "UUID") uuid="$value" ;;
            "Wake-up Type") wake_up_type="$value" ;;
        esac
    done

    os_info=$(get_os_info)
    cpu_info=$(get_cpu_info)
    ram_info=$(get_ram_info)
    nic_info=$(get_nic_info)
    disk_info=$(get_disk_info)

    # 构造 JSON 数据
    json_data=$(cat <<EOF
{
    "asset_type": "$asset_type",
    "manufacturer": "$manufacturer",
    "sn": "$sn",
    "model": "$model",
    "uuid": "$uuid",
    "wake_up_type": "$wake_up_type",
    "os_info": $os_info,
    "cpu_info": $cpu_info,
    "ram_info": $ram_info,
    "nic_info": $nic_info,
    "disk_info": $disk_info
}
EOF
)

    echo "$json_data"
}

# 获取操作系统信息
function get_os_info {
    distributor=$(lsb_release -a | grep 'Distributor ID' | awk -F: '{print $2}' | awk '{$1=$1};1')
    release=$(lsb_release -a | grep 'Description' | awk -F: '{print $2}' | awk '{$1=$1};1')
    os_type="Linux"

    json_data=$(cat <<EOF
{
    "os_distribution": "$distributor",
    "os_release": "$release",
    "os_type": "$os_type"
}
EOF
)

    echo "$json_data"
}

# 获取 CPU 信息
function get_cpu_info {
    cpu_model=$(cat /proc/cpuinfo | grep 'model name' | head -1 | awk -F: '{print $2}' | awk '{$1=$1};1')
    cpu_count=$(cat /proc/cpuinfo | grep 'processor' | wc -l)
    cpu_core_count=$(cat /proc/cpuinfo | grep 'cpu cores' | awk -F: '{SUM +=$2} END {print SUM}')

    json_data=$(cat <<EOF
{
    "cpu_model": "$cpu_model",
    "cpu_count": "$cpu_count",
    "cpu_core_count": "$cpu_core_count"
}
EOF
)

    echo "$json_data"
}

#获取内存信息还没写


# 获取物理网卡信息
function get_nic_info {
    raw_data=()
    nic_dic=()

    while IFS= read -r line; do
        parts=($line)
        nic_name=${parts[1]}
        mac_addr=${parts[2]}
        ip_addr=$(echo "${parts[3]}" | cut -d '/' -f 1)
        netmask=$(echo "${parts[3]}" | cut -d '/' -f 2)
        network=${parts[-1]}
        if [[ "$nic_name" =~ ^(eth0|ens[0-9]+)$ && "$ip_addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if [[ ! ${nic_dic["$mac_addr"]} ]]; then
                nic_dic["$mac_addr"]="{\"name\": \"$nic_name\", \"mac\": \"$mac_addr\", \"net_mask\": \"$netmask\", \"network\": \"$network\", \"bonding\": 0, \"model\": \"unknown\", \"ip_address\": \"$ip_addr\"}"
            else
                random_mac_addr="${mac_addr}_bonding_addr"
                nic_dic["$random_mac_addr"]="{\"name\": \"$nic_name\", \"mac\": \"$random_mac_addr\", \"net_mask\": \"$netmask\", \"network\": \"$network\", \"bonding\": 1, \"model\": \"unknown\", \"ip_address\": \"$ip_addr\"}"
            fi
        fi
    done < <(ip -o addr show)

    nic_list=("${nic_dic[@]}")
    json_data=$(cat <<EOF
{
    "nic": [$(IFS=,; echo "${nic_list[*]}")]
}
EOF
)

    echo "$json_data"
}

# 获取硬盘信息
function get_disk_info {
    model=$(sudo hdparm -i /dev/sda | grep Model | awk -F, '{print $1}' | cut -d '=' -f 2)
    sn=$(sudo hdparm -i /dev/sda | grep SerialNo | awk -F= '{print $2}' | tr -d '[:space:]')
    size=$(sudo fdisk -l /dev/sda | grep "Disk /dev/sda" | awk '{print $3}')

    json_data=$(cat <<EOF
{
    "physical_disk_driver": [
        {
            "model": "$model",
            "sn": "$sn",
            "size": "$size"
        }
    ]
}
EOF
)

    echo "$json_data"
}

# 收集信息
collected_data=$(collect_info)
echo "$collected_data"

# 指定目标 URL
target_url="http://10.10.10.111/api/receive_win.do"  # 替换为您的目标 URL

# 发送数据到目标 URL
response=$(curl -X POST -H "Content-Type: application/json" -d "$collected_data" "$target_url")
if [[ $? -eq 0 ]]; then
    echo "Data sent successfully."
else
    echo "Failed to send data. Response: $response"
fi
