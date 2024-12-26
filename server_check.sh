#!/bin/bash
 
clear
 
LIGHTBLUE="\033[1;34m"
RED="\033[31;1m"
GREEN="\033[32;1m"
YELLOW="\033[33;1m"
CYAN="\033[36;1m"
NC="\033[0m"
 
function set_hostname {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}HostName Setting${NC}"
    echo -e "${CYAN}==================================${NC}"
    while true; do
        echo -ne "${YELLOW}Enter the 4-digit Server Number: ${NC}"
        read server_number
 
        if ! [[ $server_number =~ ^[0-9]{4}$ ]]; then
            echo -e "${RED}Only 4-digit numbers can be entered! ${NC}"
            continue
        else
            current_hostname=$(cat /etc/hostname)
            new_hostname=$(echo $current_hostname | sed -r "s/(.*-)[0-9]{4}(\.cafe24\.com)/\1$server_number\2/")
            echo $new_hostname > /etc/hostname
            echo -e "${GREEN}HostName Set Completed.${NC}"
            echo -e "${GREEN}Result: $(cat /etc/hostname)${NC}"
            break
        fi
    done
}
 
function set_network {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}Network Setting${NC}"
    echo -e "${CYAN}==================================${NC}"
    while true; do
        read -p "Enter the IP Address: " ipaddr
 
        if ! [[ $ipaddr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo -e "${RED}Invalid IP address format. Please enter an IP address in the format xxx.xxx.xxx.xxx ${NC}"
            continue
        fi
 
        IFS='.' read -r -a ip_parts <<< "$ipaddr"
        last_octet=${ip_parts[3]}
 
        if [[ $last_octet -eq 1 ]] || [[ $last_octet -eq 129 ]]; then
            echo -e "${RED}The last octet of the IP address cannot be 1 or 129. Please enter a different IP address. ${NC}"
            continue
        fi
 
        if (( last_octet < 128 )); then
            gateway="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.1"
        else
            gateway="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.129"
        fi
 
        netmask="255.255.255.128"
        hwaddr=$(ip link | awk '/link\/ether/ {print $2; exit}')
 
        sed -i "s/^IPADDR=.*/IPADDR=$ipaddr/" /etc/sysconfig/network-scripts/ifcfg-eth0
        sed -i "s/^NETMASK=.*/NETMASK=$netmask/" /etc/sysconfig/network-scripts/ifcfg-eth0
        sed -i "s/^GATEWAY=.*/GATEWAY=$gateway/" /etc/sysconfig/network-scripts/ifcfg-eth0
        sed -i "/^HWADDR=/d" /etc/sysconfig/network-scripts/ifcfg-eth0
 
        echo "HWADDR=$hwaddr" >> /etc/sysconfig/network-scripts/ifcfg-eth0
 
        echo -e "${GREEN}Network Set Completed.${NC}"
        echo -e "${YELLOW}Result:${NC}"
        echo -e "${GREEN}IPADDR=$ipaddr${NC}"
        echo -e "${GREEN}NETMASK=$netmask${NC}"
        echo -e "${GREEN}GATEWAY=$gateway${NC}"
        echo -e "${GREEN}HWADDR=$hwaddr${NC}"
        break
    done
 
    echo ""
 
    echo -e "${YELLOW}NetworkManager Restarting...${NC}"
    ifdown eth0 >/dev/null 2>&1
    sleep 1
    ifup eth0 >/dev/null 2>&1
    sleep 1
    systemctl restart NetworkManager
    sleep 2
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}NetworkManager Restart Completed.${NC}"
    else
        echo -e "${RED}NetworkManager Restart Failed.${NC}"
        exit 1
    fi
 
    echo ""
    echo -e "${YELLOW}Gateway($gateway) Ping Testing...${NC}"
    if ping -c 2 $gateway | grep 'time='; then
        echo -e "${GREEN}Ping Test Completed.${NC}"
    else
        echo -e "${RED}Ping Test Failed.${NC}"
        exit 1
    fi
    echo ""
    echo -e "${YELLOW}DNS(naver.com) Query Testing...${NC}"
    if dig +short naver.com; then
        echo -e "${GREEN}DNS Query Test Completed.${NC}"
    else
        echo -e "${RED}DNS Query Test Failed.${NC}"
        exit 1
    fi
}
 
function set_disk {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}Disk Setting${NC}"
    echo -e "${CYAN}==================================${NC}"
 
    echo -ne "${YELLOW}Do you want to proceed with Backup Disk Setting? (Y/N): ${NC}"
    read proceed
 
    if [[ $proceed =~ [Yy] ]]; then
        OS_DISK="/dev/sda"
        BACKUP_DISK="/dev/sdb"
        EXPECTED_OS_SIZE=232
        EXPECTED_BACKUP_SIZE=931
 
        check_disk_size() {
            local disk=$1
            local expected_size=$2
            local actual_size=$(fdisk -l $disk | grep "Disk $disk" | awk '{print int($3)}')
 
            if [ "$actual_size" -ne "$expected_size" ]; then
                echo -e "${RED}Warning: The capacity of $disk is different from the expected ($expected_size GB). Actual size: $actual_size GB${NC}"
                return 1
            fi
        }
 
        execute_command() {
            local command=$1
            local success_message=$2
            local failure_message=$3
 
            if eval $command &> /dev/null; then
                echo -e "${GREEN}$success_message${NC}"
            else
                echo -e "${RED}$failure_message${NC}"
                return 1
            fi
        }
 
        if ! check_disk_size $OS_DISK $EXPECTED_OS_SIZE || ! check_disk_size $BACKUP_DISK $EXPECTED_BACKUP_SIZE; then
            return
        fi
 
        if ! execute_command "dd if=/dev/zero of=$BACKUP_DISK bs=1M count=10" \
                             "GRUB Clean Completed." \
                             "Warning: Failed to clean GRUB." || \
                             sleep 1
           ! execute_command "wipefs --all $BACKUP_DISK" \
                             "Partition Clear Completed." \
                             "Warning: Failed to Clear OS disk partition structure." || \
                             sleep 1
           ! execute_command "sfdisk -d $OS_DISK | sfdisk -f $BACKUP_DISK" \
                             "Partition Clone Completed." \
                             "Warning: Failed to clone OS disk partition structure." || \
                             sleep 1
           ! execute_command "echo -e 'd\n3\nn\np\n3\n\n\nw' | fdisk $BACKUP_DISK" \
                             "Partition Resizing Completed." \
                             "Warning: Failed to reconfigure the last partition of the BACKUP disk." || \
                             sleep 1
           ! execute_command "mkfs.xfs -f ${BACKUP_DISK}1 && mkfs.xfs -f ${BACKUP_DISK}2 && mkfs.xfs -f ${BACKUP_DISK}3 && mkswap ${BACKUP_DISK}2" \
                             "Partition Format Completed." \
                             "Warning: Failed to format the BACKUP disk."; then
            return
        fi
 
        echo ""
 
        echo -e "${GREEN}Result:${NC}" && lsblk | GREP_COLOR='01;32' grep --color=always '^.*$'
    else
        echo "Disk Setting Operation Has Been Canceled."
    fi
}
 
function set_passwd {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}Password Setting${NC}"
    echo -e "${CYAN}==================================${NC}"
 
    while true; do
        echo -ne "${YELLOW}Enter the root Password: ${NC}"
        read password
 
        if [[ ${#password} -lt 8 ]]; then
            echo -e "${RED}Password must be at least 8 characters.${NC}"
            continue
        elif ! [[ $password =~ [0-9] ]]; then
            echo -e "${RED}Password must include at least one number.${NC}"
            continue
        elif ! [[ $password =~ [a-z] ]]; then
            echo -e "${RED}Password must include at least one lowercase letter.${NC}"
            continue
        elif ! [[ $password =~ [A-Z] ]]; then
            echo -e "${RED}Password must include at least one uppercase letter.${NC}"
            continue
        elif [[ $password =~ [[:space:]] ]]; then
            echo -e "${RED}Password must not contain spaces.${NC}"
            continue
        fi
 
        echo "root:$password" | chpasswd
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}Password Set Completed.${NC}"
        else
            echo -e "${RED}Password Set Failed${NC}"
        fi
 
        break
    done
}
 
function clear_log {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}Clear Log${NC}"
    echo -e "${CYAN}==================================${NC}"
    echo -e "${YELLOW}Clearing Logs...${NC}"
    cd /var/log
 
    if [ "$(pwd)" = "/var/log" ]; then
        rm -rf boot* cron* dmesg* maillog* messages* secure* sftp* vsftpd* xferlog* wtmp* yum* lastlog*
        touch lastlog wtmp xferlog
    fi
 
    rm -rf /var/log/_*.log
    rm -rf /var/log/sa/*
    rm -rf /var/log/*-*
    rm -rf /usr/local/checker/www/system/*
 
    > /var/log/btmp
    > /root/.bash_history
 
    systemctl restart rsyslog
    dmesg -C
    sleep 1
    sync; sync && echo 3 > /proc/sys/vm/drop_caches
    echo -e "${GREEN}Clear Log Completed.${NC}"
}
 
function confirm_logout {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}Logout${NC}"
    echo -e "${CYAN}==================================${NC}"
    while true; do
        echo -ne "${YELLOW}Are You Sure You Want to Logout? (Y/N): ${NC}"
        read confirm
 
 
        case $confirm in
            [Yy]* ) echo -e "${GREEN}Logging Out...${NC}"; kill -HUP $(ps -p $$ -o ppid=); break ;;
            [Nn]* ) echo -e "${RED}Logout Canceled.${NC}"; return ;;
            * ) echo "Please Answer Yes (Y) or No (N)." ;;
        esac
    done
}
 
function confirm_reboot {
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}Reboot${NC}"
    echo -e "${CYAN}==================================${NC}"
    while true; do
        echo -ne "${YELLOW}Are You Sure You Want to Reboot? (Y/N): ${NC}"
        read confirm
 
        case $confirm in
            [Yy]* ) echo -e "${GREEN}Rebooting...${NC}"; init 6; break ;;
            [Nn]* ) echo -e "${RED}Reboot Canceled.${NC}"; return ;;
            * ) echo "Please Answer Yes (Y) or No (N)." ;;
        esac
    done
}


cpu_status="OK"
memory_status="OK"
disk_status="OK"
nic_status="OK"
system_status="OK"
os_status="OK"
etc_status="OK"
failure_reasons=""
 
 
function _Check_Base() {
    service_type="qn381 qn391 qn211 qn541"

    os_version=$(cat /etc/redhat-release | awk -F'.' '{print $1}' | awk '{print $NF}')
    server_hostname=$(hostname | awk -F'.' '{print $1}')
    hostname_type=$(hostname | awk -F'-' '{print $1}')

    if [ ${os_version} -eq 6 ]; then
        server_ip=$(ifconfig | egrep "inet addr" | egrep -v "127.0.0.1" | awk '{print $2}' | awk -F':' '{print $2}')
    elif [ ${os_version} -eq 7 ] || [ ${os_version} -eq 8 ]; then
        server_ip=$(ifconfig | egrep "inet" | egrep -v "127.0.0.1|inet6" | awk '{print $2}')
    else
        echo "invalid os version !!"
        exit 0
    fi

    check_service=$(echo ${service_type} | egrep "${hostname_type}" | wc -w)

    if [ ${check_service} -eq 0 ]; then
        echo "invalid service type (hostname) !!"
        exit 0
    fi
}
 
function _Check_Spec() {
   # check_cpu_version=$(cat /proc/cpuinfo | egrep -i "model name" | sort -u | awk '{for(i=1;i<=NF;i++){if($i~/^E[0-9]?-[0-9]/){print $i,$(i+1)}}}')
    check_cpu_version=$(cat /proc/cpuinfo | grep -i "model name" | sort -u | awk '{for(i=1;i<=NF;i++){if($i~/^E[0-9-]+/ || $i~/[0-9]{4}/){print $i}}}')
    check_cpu_count=$(cat /proc/cpuinfo | egrep -i "physical id" | sort -u | wc -l)
    check_ram=$(free -g | egrep -i "mem:" | awk '{print $2}')
    check_swap=$(free -g | egrep -i "swap:" | awk '{print $2}')



    ssd_model=$(lsblk -no MODEL /dev/sda)
    if [[ $ssd_model == *"SSD"* ]]; then
       #check_size_sda=$(lshw -businfo | grep -i disk | grep -i "/dev/sda" | awk '{print $4}' | sed 's/GB//')
        check_size_sda=$(lsblk -dn -o SIZE /dev/sda | awk '{printf "%.0f", $1}' | xargs)
    fi

    sata_model=$(lsblk -no MODEL /dev/sdb)
    if [[ $sata_model == ST* ]]; then
        sata_full_info=$(lshw -businfo | grep -i disk | grep -i "/dev/sdb" | awk '{print $5}')
        check_size_sdb=$(echo $sata_full_info | grep -oP '(?<=ST)\d{4}')
    fi


    if [ "${hostname_type}" == "qn211" ]; then
      if lsblk /dev/nvme0n1 &> /dev/null ;then
          check_size_nvme=$(lsblk -nd -o SIZE /dev/nvme0n1 2>/dev/null | awk '{printf "%.0f", $1}')
      else
          check_size_nvme=0
      fi
    fi

}
 
 
 
 
function _Check_Variable1() {
    _Check_Spec
    local fail_reasons=""

    if [ "${hostname_type}" == "qn211" ]; then
        if [ "${check_cpu_version}" == "4210" ]; then
            string_cpu_version="CPU Version OK (${check_cpu_version})"
        else
            string_cpu_version=" ** Invalid CPU Version !! (${check_cpu_version})"
            fail_reasons+="Invalid CPU Version; "
            cpu_status="FAIL"
        fi

        if [ "${check_cpu_count}" -eq 2 ]; then
            string_cpu_count="CPU Count OK (${check_cpu_count} EA)"
        else
            string_cpu_count=" ** Invalid CPU Count !! (${check_cpu_count} EA)"
            fail_reasons+="Invalid CPU Count; "
            cpu_status="FAIL"
        fi

        if [ "${check_ram}" == "30" -o "${check_ram}" == "32" ]; then
            string_ram="Pysical Memory Size OK (${check_ram} GB)"
        else
            string_ram=" ** Invalid Pysical Memory Size !! (${check_ram} GB)"
            fail_reasons+="Invalid Memory Size; "
            memory_status="FAIL"
        fi

        if [ "${check_swap}" == "3" -o "${check_swap}" == "4" ];then
            string_swap="Swap Memory Size OK (${check_swap} GB)"
        else
            string_swap=" ** Invalid Swap Memory Size !! (${check_swap} GB)"
            fail_reasons+="Invalid Swap Size; "
            memory_status="FAIL"
        fi

        if [ "${check_size_sda}" -ge 460 ] && [ "${check_size_sda}" -le 512 ]; then
        #if [ "${check_size_sda}" == "460" -o "${check_size_sda}" == "512" ]
        #then
            string_size_sda="Disk /dev/sda Size OK (${check_size_sda} GB)"
        else
            string_size_sda=" ** Invalid Disk /dev/sda Size !! (${check_size_sda} GB)"
            fail_reasons+="Invalid /dev/sda Size; "
            disk_status="FAIL"
        fi

        if [ "$(echo "${check_size_sdb} >= 1800 && ${check_size_sdb} <= 2100" | bc)" -eq 1 ]; then
            string_size_sdb="Disk /dev/sdb Size OK (${check_size_sdb} GB)"
        else
            string_size_sdb=" ** Invalid Disk /dev/sdb Size !! (${check_size_sdb} GB)"
            fail_reasons+="Invalid /dev/sdb Size; "
            disk_status="FAIL"
        fi

        if [[ "${check_size_nvme}" -ge 460 && "${check_size_nvme}" -le 470 ]]; then
            string_size_nvme="Disk /dev/nvme0n1 Size OK (${check_size_nvme} GB)"
        else
            string_size_nvme=" ** Invalid Disk /dev/nvme01 Size !! (${check_size_nvme} GB)"
            fail_reasons+="Invalid NVMe Size (${check_size_nvme} GB); "
            disk_status="FAIL"
        fi
    fi
 
############### QN541
    if [ "${hostname_type}" == "qn541" ]; then
        if [ "${check_cpu_version}" == "E5-2620" ]; then
            string_cpu_version="CPU Version OK (${check_cpu_version})"
        else
            string_cpu_version=" ** Invalid CPU Version !! (${check_cpu_version})"
            fail_reasons+="Invalid CPU Version; "
            cpu_status="FAIL"
        fi

        if [ "${check_cpu_count}" -eq 1 ]; then
            string_cpu_count="CPU Count OK (${check_cpu_count} EA)"
        else
            string_cpu_count=" ** Invalid CPU Count !! (${check_cpu_count} EA)"
            fail_reasons+="Invalid CPU Count; "
            cpu_status="FAIL"
        fi

        if [ "${check_ram}" == "15" -o "${check_ram}" == "16" ]; then
            string_ram="Pysical Memory Size OK (${check_ram} GB)"
        else
            string_ram=" ** Invalid Pysical Memory Size !! (${check_ram} GB)"
            fail_reasons+="Invalid Memory Size; "
            memory_status="FAIL"
        fi

        if [ "${check_swap}" == "3" -o "${check_swap}" == "4" ]; then
            string_swap="Swap Memory Size OK (${check_swap} GB)"
        else
            string_swap=" ** Invalid Swap Memory Size !! (${check_swap} GB)"
            fail_reasons+="Invalid Swap Size; "
            memory_status="FAIL"
        fi

        if [ "${check_size_sda}" -ge 460 ] && [ "${check_size_sda}" -le 512 ]; then
        #if [ "$(echo "${check_size_sda} >= 460 && ${check_size_sda} <= 512" | bc)" -eq 1 ]; then
            string_size_sda="Disk /dev/sda Size OK (${check_size_sda} GB)"
        else
            string_size_sda=" ** Invalid Disk /dev/sda Size !! (${check_size_sda} GB)"
            fail_reasons+="Invalid /dev/sda Size; "
            disk_status="FAIL"
        fi

        if [ "$(echo "${check_size_sdb} >= 1800 && ${check_size_sdb} <= 2000" | bc)" -eq 1 ]; then
            string_size_sdb="Disk /dev/sdb Size OK (${check_size_sdb} GB)"
        else
            string_size_sdb=" ** Invalid Disk /dev/sdb Size !! (${check_size_sdb} GB)"
            fail_reasons+="Invalid /dev/sdb Size; "
            disk_status="FAIL"
        fi
    fi


###############
 
    if [ "${hostname_type}" == "qn381" ]; then
        if [ "${check_cpu_version}" == "E3-1230" ]; then
            string_cpu_version="CPU Version OK (${check_cpu_version})"
        else
            string_cpu_version=" ** Invalid CPU Version !! (${check_cpu_version})"
            fail_reasons+="Invalid CPU Version; "
            cpu_status="FAIL"
        fi

        if [ "${check_cpu_count}" -eq 1 ]; then
            string_cpu_count="CPU Count OK (${check_cpu_count} EA)"
        else
            string_cpu_count=" ** Invalid CPU Count !! (${check_cpu_count} EA)"
            fail_reasons+="Invalid CPU Count; "
            cpu_status="FAIL"
        fi

        if [ "${check_ram}" == "15" -o "${check_ram}" == "16" ]; then
            string_ram="Pysical Memory Size OK (${check_ram} GB)"
        else
            string_ram=" ** Invalid Pysical Memory Size !! (${check_ram} GB)"
            fail_reasons+="Invalid Memory Size; "
            memory_status="FAIL"
        fi

        if [ "${check_swap}" == "3" -o "${check_swap}" == "4" ]; then
            string_swap="Swap Memory Size OK (${check_swap} GB)"
        else
            string_swap=" ** Invalid Swap Memory Size !! (${check_swap} GB)"
            fail_reasons+="Invalid Swap Size; "
            memory_status="FAIL"
        fi


        if [ "${check_size_sda}" -ge 460 ] && [ "${check_size_sda}" -le 512 ]; then
        #if [ "$(echo "${check_size_sda} >= 460 && ${check_size_sda} <= 512" | bc)" -eq 1 ]; then
            string_size_sda="Disk /dev/sda Size OK (${check_size_sda} GB)"
        else
            string_size_sda=" ** Invalid Disk /dev/sda Size !! (${check_size_sda} GB)"
            fail_reasons+="Invalid /dev/sda Size; "
            disk_status="FAIL"
        fi

        if [ "$(echo "${check_size_sdb} >= 1800 && ${check_size_sdb} <= 2000" | bc)" -eq 1 ]; then
            string_size_sdb="Disk /dev/sdb Size OK (${check_size_sdb} GB)"
        else
            string_size_sdb=" ** Invalid Disk /dev/sdb Size !! (${check_size_sdb} GB)"
            fail_reasons+="Invalid /dev/sdb Size; "
            disk_status="FAIL"
        fi
    fi
 
    if [ "${hostname_type}" == "qn391" ]; then
        if [ "${check_cpu_version}" == "E-2124" -o "${check_cpu_version}" == "E-2224" ]; then
            string_cpu_version="CPU Version OK (${check_cpu_version})"
        else
            string_cpu_version=" ** Invalid CPU Version !! (${check_cpu_version})"
            fail_reasons+="Invalid CPU Version; "
            cpu_status="FAIL"
        fi

        if [ "${check_cpu_count}" -eq 1 ]; then
            string_cpu_count="CPU Count OK (${check_cpu_count} EA)"
        else
            string_cpu_count=" ** Invalid CPU Count !! (${check_cpu_count} EA)"
            fail_reasons+="Invalid CPU Count; "
            cpu_status="FAIL"
        fi

        if [ "${check_ram}" == "15" -o "${check_ram}" == "16" ]; then
            string_ram="Pysical Memory Size OK (${check_ram} GB)"
        else
            string_ram=" ** Invalid Pysical Memory Size !! (${check_ram} GB)"
            fail_reasons+="Invalid Memory Size; "
            memory_status="FAIL"
        fi

        if [ "${check_swap}" == "3" -o "${check_swap}" == "4" ];then
            string_swap="Swap Memory Size OK (${check_swap} GB)"
        else
            string_swap=" ** Invalid Swap Memory Size !! (${check_swap} GB)"
            fail_reasons+="Invalid Swap Size; "
            memory_status="FAIL"
        fi


        if [ "${check_size_sda}" -ge 230 ] && [ "${check_size_sda}" -le 256 ]; then
            string_size_sda="Disk /dev/sda Size OK (${check_size_sda} GB)"
        else
            string_size_sda=" ** Invalid Disk /dev/sda Size !! (${check_size_sda} GB)"
            disk_status="FAIL"
        fi

        if [ "${check_size_sdb}" == "900" -o "${check_size_sdb}" == "1000" ]; then
            string_size_sdb="Disk /dev/sdb Size OK (${check_size_sdb} GB)"
        else
            string_size_sdb=" ** Invalid Disk /dev/sdb Size !! (${check_size_sdb} GB)"
            disk_status="FAIL"
        fi
    fi


    if [ "$disk_status" == "FAIL" ];then
        failure_reasons+="DISK FAIL: $fail_reasons\n"
    fi
}
 
 
 
function _Check_Common() {
    check_error=$(cat /var/log/messages | egrep -v "Firmware First mode|kernel: ipmi_si:|support is initialized.|SError|ACPI|Bringing up|BERT" | egrep -ic "error")
    check_dig=$(timeout 1s dig cafe24.com +short | wc -l)
    check_thttpd=$(netstat -tunlp | egrep -c "thttpd")
    check_opt=$(ls -al /opt | egrep -c "APM_v[0-9]{3}.tar.gz")
    check_disk_count=$(fdisk -l  | egrep -ic "^disk /dev")
    check_partition_sda=$(fdisk -l /dev/sda | egrep -c "sda[0-9]")
    check_partition_sdb=$(fdisk -l /dev/sdb | egrep -c "sdb[0-9]")
    check_home_file=$(ls /home | egrep -v 'lost\+found' | wc -w)
    check_network_device=$(ifconfig | egrep -c "eth0|eno1")

    if [ "${hostname_type}" == "q361" -o "${hostname_type}" == "qn211" ]; then
        check_home_nvme=$(df -h | egrep "/home" | egrep "nvme" | wc -l)
        check_rclocal_nvme=$(cat /etc/rc.local | egrep -v "^#|^$" | egrep -c "mount|echo")
    fi
}
 
 
function _Check_Variable2() {
    _Check_Common
    local fail_reasons=""

    if [ ${check_error} -eq 0 ]; then
        string_error="Error Log OK"
    else
        string_error=" ** Invalid Error Log !!"
        fail_reasons+="Invalid Error Log; "
        etc_status="FAIL"
    fi

    if [ ${check_dig} -ge 1 ]; then
        string_dig="Dig Test OK"
    else
        string_dig=" ** Invalid Dig Test !!"
        fail_reasons+="Invalid Dig Test; "
        etc_status="FAIL"
    fi

    if [ ${check_thttpd} -eq 1 ]; then
        string_thttpd="thttpd Port OK"
    else
        /usr/local/checker/sbin/thttpd -C /usr/local/checker/etc/thttpd.conf
        check_thttpd=$(netstat -tunlp | grep -w "thttpd" | wc -l)
        if [ ${check_thttpd} -ge 1 ]; then
            string_thttpd="Start thttpd port and Successed OK"
        else
            string_thttpd=" ** thttpd Port: FAIL **"
        fi
    fi

    if [ ${check_opt} -ge 1 ]; then
        string_opt="/opt/APM_vXX.tar.gz OK"
    else
        string_opt=" ** Invalid /opt/APM_vXX.tar.gz !!"
        fail_reasons+="Invalid /opt/APM_vXX.tar.gz; "
        etc_status="FAIL"
    fi
 
    if [ ${check_partition_sda} -eq 3 ]; then
        string_partition_sda="Disk /dev/sda Partition OK"
    else
        string_partition_sda=" ** Invalid Disk /dev/sda Partition !!"
        fail_reasons+="Invalid /dev/sda Partition; "
        disk_status="FAIL"
    fi

    if [ ${check_partition_sdb} -eq 3 ]; then
        string_partition_sdb="Disk /dev/sdb Partition OK"
    else
        string_partition_sdb=" ** Invalid Disk /dev/sdb Partition !!"
        fail_reasons+="Invalid /dev/sdb Partition; "
        disk_status="FAIL"
    fi

    if [ ${check_disk_count} -eq 2 ]; then
        string_disk_count="Disk Count OK (${check_disk_count} EA)"
    else
        string_disk_count=" ** Invalid Diks Count !! (${check_disk_count} EA)"
        fail_reasons+="Invalid Disk Count; "
        disk_status="FAIL"
    fi

    if [ ${check_home_file} -eq 0 ]; then
        string_home_file="Partition /home Check OK"
    else
        string_home_file=" ** Invalid /home Partition !!"
        fail_reasons+="Invalid /home Partition; "
        etc_status="FAIL"
    fi

    if [ ${check_network_device} -eq 0 ]; then
        string_network_device=" ** Invalid Network Device !!"
        fail_reasons+="Invalid Network Device; "
        nic_status="FAIL"
    else
        string_network_device="Network Device OK"
    fi

    if [ "${hostname_type}" == "qn211" ]; then
        if [ ${check_home_nvme} -eq 1 ]; then
            string_home_nvme="NVMe /home Mount OK"
        else
            string_home_nvme=" ** Invalid NVMe /home Mount !!"
            fail_reasons+="Invalid NVMe Mount; "
            disk_status="FAIL"
        fi

        if [ ${check_rclocal_nvme} -eq 2 ]; then
            string_rclocal_nvme="NVMe rc.local OK"
        else
            string_rclocal_nvme=" ** Invalid NVMe rc.local !!"
            fail_reasons+="Invalid NVMe rc.local; "
            etc_status="FAIL"
        fi
        if [ ${check_disk_count} -eq 3 ]; then
            string_disk_count="Disk Count OK (${check_disk_count} EA)"
        else
            string_disk_count=" ** Invalid Diks Count !! (${check_disk_count} EA)"
            fail_reasons+="Invalid Disk Count; "
            disk_status="FAIL"
        fi
    fi
 
     
    if [ "$etc_status" == "FAIL" ]; then
        failure_reasons+="ETC FAIL: $fail_reasons\n"
    fi
}
 
 
function _Check_Mount() {
    mkdir -p /disk
    mount /dev/sdb3 /disk

    mkdir -p /disk/boot
    mount /dev/sdb1 /disk/boot

    touch /disk/CAFE24_TEST
    touch /disk/boot/CAFE24_TEST

    check_exist_sdb3=$(ls /disk/CAFE24_TEST | wc -w)
    check_exist_sdb1=$(ls /disk/boot/CAFE24_TEST | wc -w)

    if [ ${check_exist_sdb3} -eq 1 -a ${check_exist_sdb1} -eq 1 ]; then
        string_mount_sdb="Disk /dev/sdb Mount OK"
    else
        string_mount_sdb=" ** Invalid Disk /dev/sdb Mount !!"
        disk_status="FAIL"
        failure_reasons+="Disk Mount Fail: /dev/sdb Mount Failure\n"
    fi

    rm -rf /disk/CAFE24_TEST
    rm -rf /disk/boot/CAFE24_TEST

    umount /dev/sdb1
    umount /dev/sdb3
}


function status_color {
    if [ "$1" == "OK" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi
}
 
 
function system_info {
    echo -e "---------------------------------------------------------"
    echo -e "${YELLOW}SYSTEM INFORMATION :: SYSTEM $(status_color ${system_status})${NC}\n"
    echo -e "Model  : $(dmidecode -s baseboard-product-name)"
    echo -e "Vendor : $(dmidecode -s baseboard-manufacturer)"
}


function os_info {
    echo -e "---------------------------------------------------------"
    echo -e "${YELLOW}SYSTEM INFORMATION :: OS $(status_color ${os_status})${NC}\n"
    echo -e "RELEASE : $(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '\"')"
    echo -e "Kernel  : $(uname -r)"
    echo -e "OpenSSL : $(openssl version)"
    echo -e "OpenSSH : $(ssh -V 2>&1 | awk '{print $1, $2}')"
}


function cpu_info {
    echo -e "---------------------------------------------------------"
    echo -e "${YELLOW}SYSTEM INFORMATION :: CPU $(status_color ${cpu_status})${NC}\n"
    cpu_info=$(lscpu)
    l3_cache=$(echo "$cpu_info" | grep 'L3 cache' | awk '{print $3}')
    l3_cache_kb=$(( ${l3_cache%K} * 1024 ))
    cpu_mhz=$(echo "$cpu_info" | grep 'CPU MHz' | awk '{print $3}')
    model_name=$(echo "$cpu_info" | grep 'Model name' | head -n 1 | cut -d ':' -f 2 | xargs)
    cores_per_socket=$(echo "$cpu_info" | grep 'Core(s) per socket' | awk '{print $4}')
    threads_per_core=$(echo "$cpu_info" | grep 'Thread(s) per core' | awk '{print $4}')
    hyper_threading=$(if [ "$threads_per_core" -gt 1 ]; then echo "${GREEN}Enabled${NC}"; else echo "${RED}Disabled${NC}"; fi)
    number_of_cpus=$(echo "$cpu_info" | grep 'Socket(s)' | awk '{print $2}')
    total_cores=$(echo "$cpu_info" | grep '^CPU(s)' | awk '{print $2}')

    echo -e "Lcache size   : ${l3_cache_kb}KB"
    echo -e "cpu MHz       : $cpu_mhz"
    echo -e "model name    : $model_name"
    echo -e "Processor type: $cores_per_socket Core (${CYAN}HyperThread${NC}: $hyper_threading)"
    echo -e "Number of CPU : $number_of_cpus"
    echo -e "Total Cores   : $total_cores"
}
 
 
function memory_info {
    echo -e "---------------------------------------------------------"
    echo -e "${YELLOW}SYSTEM INFORMATION :: MEMORY $(status_color ${memory_status})${NC}\n"
    echo -e "========================================================="
    printf "%-20s %-10s %-15s %-15s %-20s\n" "SLOT" "TYPE" "CLOCK" "SIZE" "PART_NUMBER"
    echo -e "---------------------------------------------------------------------------"

    dmidecode -t memory | awk '
    /Memory Device/ {device++}
    /^[[:space:]]+Size:/ {if (device) {split($0, a, ": "); size[device] = (a[2] == "No Module Installed" ? "----" : a[2])}}
    /^[[:space:]]+Speed:/ && !/Configured Memory Speed/ {if (device) {split($0, a, ": "); speed[device] = (a[2] == "Unknown" ? "----" : a[2])}}
    /^[[:space:]]+Type:/ {if (device) {split($0, a, ": "); type[device] = (a[2] == "Unknown" ? "----" : a[2])}}
    /^[[:space:]]+Part Number:/ {if (device) {split($0, a, ": "); part[device] = (a[2] == "Not Specified" ? "----" : a[2])}}
    /^[[:space:]]+Locator:/ {if (device) {split($0, a, ": "); locator[device] = a[2]}}
    /^[[:space:]]+Bank Locator:/ {if (device) {split($0, a, ": "); loc = a[2]; split(loc, parts, "_"); channel = substr(parts[3], length(parts[3])); slot[device] = "Ch" channel " " locator[device]}}
    END {
        for (i = 1; i <= device; i++) {
            printf "%-20s %-10s %-15s %-15s %-20s\n", (slot[i] ? slot[i] : "----"), (type[i] ? type[i] : "----"), (speed[i] ? speed[i] : "----"), (size[i] ? size[i] : "----"), (part[i] ? part[i] : "----")
        }
    }'

    echo -e "---------------------------------------------------------------------------"
    total_slots=$(dmidecode -t memory | grep -c "Memory Device")
    empty_slots=$(dmidecode -t memory | grep "Size: No Module Installed" | wc -l)
    total_memory=$(free -h | grep "Mem:" | awk '{print $2}')
    echo -e "Total Slot: $total_slots / Empty Slot: $empty_slots / Total Memory: $total_memory"
    echo -e "========================================================="
}


function nic_info {
    echo -e "---------------------------------------------------------"
    echo -e "${YELLOW}SYSTEM INFORMATION :: NIC $(status_color ${nic_status})${NC}\n"
    echo -e "Name\tStatus\tSpeed\tSpec"
    echo -e "---------------------------------------------------------"
    for nic in $(ls /sys/class/net/ | grep ^eth); do
        if [[ $nic != "lo" ]]; then
            status=$(cat /sys/class/net/$nic/operstate)
            speed=$(cat /sys/class/net/$nic/speed 2>/dev/null || echo "N/A")
            if [ "$status" == "up" ]; then
                status="${GREEN}yes${NC}"
            else
                status="${CYAN}no${NC}"
            fi
            if [ "$speed" == "-1" ]; then
                speed="0"
            fi
            echo -e "$nic\t$status\t${speed}Mbps\t${speed}Mbps"
        fi
    done
    echo -e "---------------------------------------------------------"
}

 
 
function disk_info {
    disk_status="OK"
    echo -e "\n${YELLOW}SYSTEM INFORMATION :: DISK $(status_color ${disk_status})${NC}\n"
    echo -e "PHYSICAL"
    echo -e "---------------------------------------------------------"
    echo -e "#\t\tTYPE\tSIZE\tRSIZE\tSTATE"
    echo -e "---------------------------------------------------------"


    devices=$(lsblk -nd -o NAME)


    for device in $devices; do
        model=$(sudo smartctl -i /dev/$device | grep -E "Device Model|Model Number" | awk -F': ' '{print $2}' | xargs)
        size=""
        type=""

        if [[ $model == *"SSD"* ]]; then
            type="SSD"
            size=$(echo $model | grep -o '[0-9]\+GB')
        elif [[ $model == ST* ]]; then
            type="SATA"
            size=$(echo $model | grep -o 'ST[0-9]\+' | grep -o '[0-9]\+')
            size="${size}GB"
        elif sudo nvme list | grep -q "/dev/$device"; then
            type="NVMe"
            size=$(echo $model | grep -o '[0-9]\+GB')
        else
            type="Unknown"
            size="Unknown"
            echo "Disk Status Set to FAIL: Unknown device type for $device ($model)"
            disk_status="FAIL"
        fi

        rsize=$(lsblk -nd -o SIZE /dev/$device)
        serial=$(udevadm info --query=all --name=/dev/$device | grep ID_SERIAL_SHORT= | cut -d'=' -f2)
        state=$(sudo smartctl -H /dev/$device | grep "SMART overall-health self-assessment test result" | awk -F': ' '{print $2}' | xargs)
        if [ "$state" == "PASSED" ]; then
            state="${GREEN}OK${NC}"
        else
            state="${CYAN}FAIL${NC}"
            disk_status="FAIL"
            echo "Disk Status Set to FAIL: SMART check failed for $device ($model)"
        fi

        if [[ -z "$size" ]]; then
            size="$rsize"
        fi

        echo -e "/dev/$device\t$type\t$size\t$rsize\t$state($serial)"
    done
    echo -e "---------------------------------------------------------"
 
 
    echo -e "\n${YELLOW}SYSTEM INFORMATION :: DISKSMART${NC}\n"

    DISKS=$(lsblk -dn -o NAME,TYPE | grep 'disk\|nvme' | awk '{print "/dev/"$1}')

    for DISK in $DISKS; do
      if [[ $DISK == /dev/nvme* ]]; then
        continue
      fi

      SMART_DATA=$(sudo smartctl -a $DISK)

      DEVICE_MODEL=$(echo "$SMART_DATA" | grep -i "Device Model" | awk -F: '{print $2}' | xargs)
      if [ -z "$DEVICE_MODEL" ]; then
        DEVICE_MODEL=$(echo "$SMART_DATA" | grep -i "Model Number" | awk -F: '{print $2}' | xargs)
      fi

      if echo "$DEVICE_MODEL" | grep -q "SSD"; then
        echo -e "${YELLOW}S.M.A.R.T Attribute Values for $DISK (SSD):${NC}"
        health_status=$(echo "$SMART_DATA" | grep -i "SMART overall-health self-assessment test result" | awk '{print $6}')
        reallocated_sector_count=$(echo "$SMART_DATA" | grep -i "Reallocated_Sector_Ct" | awk '{print $10}')
        power_on_hours=$(echo "$SMART_DATA" | grep -i "Power_On_Hours" | awk '{print $10}')
        wear_leveling_count=$(echo "$SMART_DATA" | grep -i "Wear_Leveling_Count" | awk '{print $10}')
        total_lbas_written=$(echo "$SMART_DATA" | grep -i "Total_LBAs_Written" | awk '{print $10}')

        max_wear_leveling_count=100
        remaining_life_percent=$(awk "BEGIN {printf \"%.2f\", (1 - $wear_leveling_count / $max_wear_leveling_count) * 100}")

        total_lbas_written_gb=$(awk "BEGIN {printf \"%.2f\", $total_lbas_written * 512 / (1024^3)}")

        display_value() {
          name=$1
          value=$2
          if [ -n "$value" ]; then
            if [ "$name" == "Health Status" ]; then
              if [ "$value" == "PASSED" ]; then
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              fi
            elif [ "$name" == "Remaining Life (%)" ]; then
              if (( $(echo "$value == 30.00" | bc -l) )); then
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              fi
           elif [ "$name" == "Wear Leveling Count" ]; then
             if (( $(echo "$value >= 500" | bc -l) )); then
               printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
             else
               printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
             fi  
            elif [ -z "$value" ] || [ "$value" == "-" ]; then
              printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
            elif [ "$value" -eq "$value" ] 2>/dev/null; then
              if [ "$value" -eq 0 ]; then
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              fi
            else
              printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
            fi
          fi
        }
 
        display_value "Health Status" "$health_status"
        display_value "Reallocated Sector Count" "$reallocated_sector_count"
        display_value "Power On Hours" "$power_on_hours"
        display_value "Wear Leveling Count" "$wear_leveling_count"
        display_value "Remaining Life (%)" "$remaining_life_percent"
        display_value "Total LBAs Written (GB)" "$total_lbas_written_gb"
        echo "--------------------------------------"

      elif echo "$DEVICE_MODEL" | grep -q "^ST"; then
        echo -e "${YELLOW}S.M.A.R.T Attribute Values for $DISK (SATA):${NC}"
        RAW_READ_ERROR_RATE=$(echo "$SMART_DATA" | grep "Raw_Read_Error_Rate")
        REALLOCATED_SECTOR_CT=$(echo "$SMART_DATA" | grep "Reallocated_Sector_Ct")
        SEEK_ERROR_RATE=$(echo "$SMART_DATA" | grep "Seek_Error_Rate")
        SPIN_RETRY_COUNT=$(echo "$SMART_DATA" | grep "Spin_Retry_Count")
        CURRENT_PENDING_SECTOR=$(echo "$SMART_DATA" | grep "Current_Pending_Sector")
        OFFLINE_UNCORRECTABLE=$(echo "$SMART_DATA" | grep "Offline_Uncorrectable")
        UDMA_CRC_ERROR_COUNT=$(echo "$SMART_DATA" | grep "UDMA_CRC_Error_Count")

        display_value() {
          attribute=$1
          value=$(echo $attribute | awk '{print $NF}')
          name=$(echo $attribute | awk '{print $2}')
          if [ -n "$value" ]; then
            if [ -z "$value" ] || [ "$value" == "-" ]; then
              printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
            elif [ "$value" -eq "$value" ] 2>/dev/null; then
              if [ "$value" -eq 0 ]; then
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              fi
            else
              printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
            fi
          fi
        }

        display_value "$RAW_READ_ERROR_RATE"
        display_value "$REALLOCATED_SECTOR_CT"
        display_value "$SEEK_ERROR_RATE"
        display_value "$SPIN_RETRY_COUNT"
        display_value "$CURRENT_PENDING_SECTOR"
        display_value "$OFFLINE_UNCORRECTABLE"
        display_value "$UDMA_CRC_ERROR_COUNT"

        echo "--------------------------------------"
 
      fi
      echo
    done

    if command -v nvme &> /dev/null; then
      NVME_DEVICES=$(nvme list | awk 'NR>2 {print $1}')
      if [ -n "$NVME_DEVICES" ]; then
        for device in $NVME_DEVICES; do
          SMART_DATA=$(smartctl -a "$device")

          critical_warning=$(echo "$SMART_DATA" | grep "Critical Warning" | awk '{print $3}')
          available_spare=$(echo "$SMART_DATA" | grep -w "Available Spare:" | awk '{print $3}' | sed 's/%//')
          percentage_used=$(echo "$SMART_DATA" | grep "Percentage Used" | awk '{print $3}' | sed 's/%//')
          media_errors=$(echo "$SMART_DATA" | grep "Media and Data Integrity Errors" | awk '{print $6}')
          error_log_entries=$(echo "$SMART_DATA" | grep "Error Information Log Entries" | awk '{print $5}')
          unsafe_shutdowns=$(echo "$SMART_DATA" | grep "Unsafe Shutdowns" | awk '{print $3}')

          display_value() {
            name=$1
            value=$2
            if [ -n "$value" ]; then
              if [ "$name" == "Critical Warning" ]; then
                if [ "$value" == "0x00" ]; then
                  printf "${GREEN}%-35s %10s${NC}\n" "$name" "$value"
                else
                  printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
                fi
              elif [ "$name" == "Available Spare (%)" ]; then
                if [ "$value" -ge 50 ]; then
                  printf "${GREEN}%-35s %10s${NC}\n" "$name" "$value"
                else
                  printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
                fi
              elif [ -z "$value" ] || [ "$value" == "-" ]; then
                printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
              elif [ "$value" -eq "$value" ] 2>/dev/null; then
                if [ "$value" -eq 0 ]; then
                  printf "${GREEN}%-35s %10s${NC}\n" "$name" "$value"
                else
                  printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
                fi
              else
                printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
              fi
            fi
          }

          echo -e "${YELLOW}S.M.A.R.T Attribute Values for $device (NVMe):${NC}"
          display_value "Critical Warning" "$critical_warning"
          display_value "Available Spare (%)" "$available_spare"
          display_value "Percentage Used (%)" "$percentage_used"
          display_value "Media and Data Integrity Errors" "$media_errors"
          display_value "Error Information Log Entries" "$error_log_entries"
          display_value "Unsafe Shutdowns" "$unsafe_shutdowns"
          echo "--------------------------------------"
        done
      fi
    fi
}
function final_result {
    echo -e "---------------------------------------------------------"
    echo -e "${YELLOW}SYSTEM INFORMATION :: BASE${NC}"
    echo -e "HostName : $(hostname)"
    ip_address=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
    echo -e "IP: $ip_address"
    ipmi_ip=$(ipmitool lan print 1 | grep -i "IP Address  " | head -n 1 | awk '{print $4}')
    echo -e "IPMI IP: $ipmi_ip"
    echo -e "---------------------------------------------------------"
    system_info
    os_info
    cpu_info
    memory_info
    nic_info
    disk_info
    echo -e "--------------------------------------------------------"
    echo -e "${CYAN}               Cross Check Result                      ${NC} "
    echo -e "${YELLOW}SYSTEM INFORMATION :: ETC $(status_color ${etc_status})${NC}"
    echo -e " HostName: ${YELLOW}$(hostname)${NC} "
    echo -e " IP: ${YELLOW}$ip_address${NC}"
    echo -e " IPMI IP: ${YELLOW}$ipmi_ip${NC}"
    echo -e " OS: ${YELLOW}$(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '\"' | sed 's/ (.*)//')${NC}"
    echo -e " CPU Check: $(status_color ${cpu_status})"
    echo -e " MEMORY Check: $(status_color ${memory_status})"
    echo -e " DISK Check: $(status_color ${disk_status})"
    echo -e " NIC Check: $(status_color ${nic_status})"
    echo -e " OS Check: $(status_color ${os_status})"
    echo -e "\n Error Log: $(if [ ${check_error} -eq 0 ]; then echo "${GREEN}OK${NC}"; else echo "${RED}FAIL${NC}"; fi)"
    echo -e " Dig Test: $(if [ ${check_dig} -ge 1 ]; then echo "${GREEN}OK${NC}"; else echo "${RED}FAIL${NC}"; fi)"
    echo -e " thttpd Port: $(if [ ${check_thttpd} -ge 1 ]; then echo "${GREEN}OK${NC}"; else echo "${RED}FAIL${NC}"; fi)"
    echo -e " /opt/APM_vXX.tar.gz: $(if [ ${check_opt} -ge 1 ]; then echo "${GREEN}OK${NC}"; else echo "${RED}FAIL${NC}"; fi)"
    echo -e " Partition /home Check: $(if [ ${check_home_file} -eq 0 ]; then echo "${GREEN}OK${NC}"; else echo "${RED}FAIL${NC}"; fi)"
    echo -e " Network Device: $(if [ ${check_network_device} -gt 0 ]; then echo "${GREEN}OK${NC}"; else echo "${RED}FAIL${NC}"; fi)"
    echo -e "--------------------------------------------------------"
    if [ -n "$failure_reasons" ]; then
        echo -e "${RED}Cause of failure:${NC}"

        echo -e "${failure_reasons}" | sed 's/; /\n          /g'
    fi
}
 
 
function cross_check {
    failure_reasons=""
    _Check_Base
    _Check_Variable1
    _Check_Variable2
    _Check_Mount
    final_result
}
 
 
 
while true; do
    echo -e "${CYAN}\n==================================${NC}"
    echo -e "${CYAN}  ##    ##   ####  ####   ##     # ${NC}"
    echo -e "${CYAN} #  #  #  #  #     #     #  #   ## ${NC}"
    echo -e "${CYAN} #     #  #  ###   ###      #  # # ${NC}"
    echo -e "${CYAN} #     ####  #     #       #   #### ${NC}"
    echo -e "${CYAN} #  #  #  #  #     #      #      # ${NC}"
    echo -e "${CYAN}  ##   #  #  #     ####  ####    # ${NC}"
    echo -e "${CYAN}==================================${NC}"
    echo "1. HostName Set"
    echo "2. Network Set"
    echo "3. Disk Set"
    echo "4. Passwd Set"
    echo "5. Clear Log"
    echo "6. Cross Check"
    echo "=================================="
    echo "E. Logout"
    echo "R. Reboot"
    echo "Q. Exit"
    echo "=================================="
    read -p "Enter Your Choice: " choice
    echo "----------------------------------"
 
    case $choice in
        1) clear; set_hostname ;;
        2) clear; set_network ;;
        3) clear; set_disk ;;
        4) clear; set_passwd ;;
        5) clear; clear_log ;;
        6) clear; cross_check ;; 
        E|e) clear; confirm_logout ;;
        R|r) clear; confirm_reboot ;;
        Q|q) echo "Exiting..."; exit 0 ;;
        *) echo -e "${RED}Invalid Option. Please Try Again.${NC}" ;;
    esac
done