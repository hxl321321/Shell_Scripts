#!/bin/bash
# export LANG=zh_CN.UTF-8
# DESCRIPTION: Scan the available IP addresses in the ipv4 segment on linux.
# AUTHOR: Xiaolong He
# DATE: 2023 07-18


#用户输入IP段
IPADDR=false

#对输入的IP地址做合规判断
while [[ $IPADDR = false ]]; do
IPADDR=false
    read -p "Please enter an ipv4 address segment, like [192.168.10]: " IPV4
    if [[ $(echo $IPV4 | awk -F. '{ print NF }') -eq 3 ]]; then
    for i in $(echo $IPV4 | awk -F. '{print $1,$2,$3}'); do
        if [[ $i =~ ^[1-9][0-9]{0,2}$ && $i -ge 1 && $i -le 255 ]]; then
            IPADDR=true
        else
            echo -e "Input ipv4 entered is wrong, please enter the correct ipv4 segment!"
            IPADDR=false
            break
        fi
    done
    else
        echo -e "Input ipv4 entered is wrong, please enter the correct ipv4 segment!"
    fi
done

FIRST=false
SECOND=false
START=1
END=254

while [[ $FIRST = false || $SECOND = false || $START -gt $END ]]; do
    #输入起始地址
    read -p "Please enter the starting IP address to scan (for example: 1): " START
    #对输入的起始地址做判断
    if [[ $START -ge 1 && $START -le 254 && $START =~ ^[1-9][0-9]{0,2}$ ]]; then
        FIRST=true
    else
        echo -e "Input $START entered is wrong, please enter the correct starting IP address!"
        FIRST=false
        continue
    fi

    read -p "Please enter the ending IP address to scan (for example: 255): " END
    #对输入的终止地址做判断
    if [[ $END -ge 1 && $END -le 254 && $END =~ ^[1-9][0-9]{0,2}$ ]]; then
        SECOND=true
    else
        echo -e "Input $END entered is wrong, please enter the correct ending IP address!"
        SECOND=false
        continue
    fi
done

echo "Scanning..."

for ((i=$START;i<=$END;i++)); do
    (ping $IPV4.$i -c 1 -w 1 &>/dev/null
    if [ $? -eq 0 ]; then
        echo $IPV4.$i >> used_ip.text
    else
        echo $IPV4.$i >> unused_ip.text
    fi)&
done
wait
#输出使用的IP地址
echo "-------------used ip detail------------------"
if [ -f used_ip.text ]; then
    sort -t'.' -k 4n used_ip.text
    rm -rf used_ip.text
else
    echo ""
fi
#输出未使用的IP地址
echo "-----------unused ip detail------------------"
if [ -f unused_ip.text ]; then
    sort -t'.' -k 4n unused_ip.text
    rm -rf unused_ip.text
else
    echo ""
fi