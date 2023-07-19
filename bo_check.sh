#!/bin/bash
# export LANG=zh_CN.UTF-8
# DESCRIPTION: Nagios Plugin for checking status of network bond DEVICEs on linux.
# AUTHOR: Xiaolong He
# DATE: 2022 09-13

PRODUCT=`dmidecode -s system-product-name` 
TMP=`mktemp`
IPV4=`ip -4 a |grep -vwE "virbr0|valid_lft|lo" |awk '{print $2}' |tr -d '\n' |sed 's#/[0-9][0-9]#\n#g'`

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE=$STATE_OK
STATE_MESSAGE=""
IP_LIST=(
143
168
16
)  #ipv4第2位：143生产，168心跳，16带外管理

function set_ok {
  if [ $STATE -ne $STATE_OK ]
  then
    STATE=$STATE_OK
  fi
}

function set_warning {
  if [ $STATE -ne $STATE_WARNING ]
  then
    STATE=$STATE_WARNING
  fi
}

function set_critical {
  if [ $STATE -ne $STATE_CRITICAL ]
  then
    STATE=$STATE_CRITICAL
  fi
}
function set_unknown {
  if [ $STATE -ne $STATE_UNKNOWN ]
  then
    STATE=$STATE_UNKNOWN
  fi
}

function write_status {
  case $STATE in
     0) echo -e "OK: $1\n" ;;
     1) echo -e "WARNING: $1\n" ;;
     2) echo -e "CRITICAL: $1\n" ;;
     3) echo -e "UNKNOWN: $1\n" ;;
  esac
}


function echo_line {
  echo -e "\n+------------------------------------------------------+\n"
}

function machine_type {
  echo $PRODUCT | grep -qi "virtual" 
  if [ $? -eq 0 ]
  then
    echo  "This is an 'Virirtual machine': $PRODUCT"
  else
    echo  "This is an 'Physical machine': $PRODUCT"
  fi
}


function bonds_status {
if [ -d /proc/net/bonding ]
then
  ls -1 /proc/net/bonding > $TMP
  while read -r name
  do
      TOTAL=`grep "Slave Interface" /proc/net/bonding/$name | wc -l`
      UP=`grep ": up" /proc/net/bonding/$name | wc -l`
      DOWN=`grep "down" /proc/net/bonding/$name | wc -l`
      DETAILS=`grep -E "Bonding Mode:|Currently Active Slave:|Slave Interface:|MII Status:|Speed:" /proc/net/bonding/$name`
      if [ $? -eq 0 ]
      then
        if [ $DOWN -ne 0 ]
        then
           if [ $UP -eq 0 ]
          then
            set_critical
            STATE_MESSAGE="$name bond all DEVICEs down
$DETAILS"
          else
            set_warning
            STATE_MESSAGE="$name bond has some DEVICEs down
$DETAILS"
          fi
        elif [ $UP -eq 2 ]
          then
            set_warning
            STATE_MESSAGE="$name bond just have one DEVICE
$DETAILS"
        else
          set_ok
          STATE_MESSAGE="$name bond is OK
$DETAILS"
        fi
      else
        set_unknown
        STATE_MESSAGE="unknown error"
      fi
      write_status "$STATE_MESSAGE"
  done < $TMP
else
set_critical
STATE_MESSAGE="no search bonds"
write_status "$STATE_MESSAGE"
fi
rm -f $TMP
#exit $STATE
}
function ipaddr_classification {
  declare -a HOST_IPV4
  i=0
  for addrinfo in `echo "$IPV4"`
do
        HOST_IPV4[$i]=$addrinfo
        i=$i+1
done

if [ ${#HOST_IPV4[@]} -gt 0 ]
then
  for k in "${HOST_IPV4[@]}"
do
echo $k
DEVICE=`echo $k | awk -F':' '{print $1}'`
ADDRESS=`echo $k | awk -F':' '{print $2}'`
SECADDR=`echo $ADDRESS | awk -F'.' '{print $2}' `
    if [[ ${IP_LIST[@]/${SECADDR}/} != ${IP_LIST[@]} ]] #判断是否包含在数组清单中
    then
      case $SECADDR in
      168) echo  "$DEVICE has Heartbeat address: $ADDRESS" ;;
      16) echo "$DEVICE has In band address: $ADDRESS" ;;
      143) echo "$DEVICE has Production address: $ADDRESS" ;;
      esac
     else
      echo "$DEVICE has Unknown address: $ADDRESS"
    fi
done
else
  echo "No Search IPV4 Info "
fi
}

function main {
  echo_line
  machine_type
  echo_line
  bonds_status
  echo_line
  ipaddr_classification
  echo_line
}
main